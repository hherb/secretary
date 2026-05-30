// Pins the user-message surface for every AppError + AppWarning variant.
// A new Rust variant added without a TS-side counterpart breaks the
// discriminated union (`userMessageFor` becomes non-exhaustive at the
// switch and tsc rejects compile). The `it.each` block guarantees every
// known variant produces a non-empty title — silent fall-through to a
// blank toast becomes a test failure.

import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  userMessageFor,
  userMessageForWarning,
  APP_ERROR_CODES,
  APP_WARNING_CODES,
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
    { code: 'invalid_field_value', field_name: 'seed' },
    { code: 'record_save_failed' },
    { code: 'vault_folder_not_empty', path: '/x' },
    { code: 'vault_create_failed' },
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

// Runtime fall-through gate: a future-Rust variant whose TS counterpart
// hasn't shipped must produce a logged "Unknown error" toast rather than
// `undefined`. The TS exhaustiveness check is build-time; this is the
// runtime backstop that prevents blank toasts in the field.
describe('userMessageFor — runtime fallback for unknown code', () => {
  afterEach(() => vi.restoreAllMocks());

  it('returns Unknown error message for a code not in the union', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const msg = userMessageFor({ code: 'future_variant_v2' } as unknown as AppError);
    expect(msg.title).toBe('Unknown error');
    expect(msg.detail).toContain('future_variant_v2');
    expect(errorSpy).toHaveBeenCalled();
  });

  it('returns Unknown warning message for a warning code not in the union', () => {
    const errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    const msg = userMessageForWarning({
      code: 'future_warning_v2'
    } as unknown as AppWarning);
    expect(msg.title).toBe('Unknown warning');
    expect(msg.detail).toContain('future_warning_v2');
    expect(errorSpy).toHaveBeenCalled();
  });
});

describe('vault create error codes', () => {
  it('vault_folder_not_empty surfaces the path + subfolder hint', () => {
    const m = userMessageFor({ code: 'vault_folder_not_empty', path: '/Users/h/Docs' });
    expect(m.title).toMatch(/empty/i);
    expect(m.detail).toContain('/Users/h/Docs');
    expect(m.actionHint).toMatch(/subfolder/i);
  });

  it('vault_create_failed has a retry hint', () => {
    const m = userMessageFor({ code: 'vault_create_failed' });
    expect(m.title).toMatch(/create/i);
    expect(m.actionHint).toMatch(/try again/i);
  });
});

describe('edit error codes', () => {
  it('invalid_field_value names the field', () => {
    const m = userMessageFor({ code: 'invalid_field_value', field_name: 'seed' });
    expect(m.title).toMatch(/invalid/i);
    expect(JSON.stringify(m)).toContain('seed');
  });

  it('record_save_failed has a retry hint', () => {
    const m = userMessageFor({ code: 'record_save_failed' });
    expect(m.title).toMatch(/save/i);
    expect(m.actionHint).toMatch(/try again/i);
  });
});

describe('new browse error codes', () => {
  it.each(['block_not_found', 'record_not_found', 'field_not_found'])(
    '%s maps to a non-empty title',
    (code) => {
      const err = (
        code === 'block_not_found' ? { code, block_uuid_hex: 'ab' }
        : code === 'record_not_found' ? { code, record_uuid_hex: 'ab' }
        : { code, field_name: 'x' }
      ) as AppError;
      expect(userMessageFor(err).title.length).toBeGreaterThan(0);
    }
  );
});

// Lock the runtime allowlist against the type union: any change to the
// `AppError` / `AppWarning` discriminants must also update the
// `APP_*_CODES` arrays, because `ipc.ts::isAppError` uses them at runtime.
// Drift between the two would let an unknown code slip through the IPC
// guard and fall into the runtime fallback above — desired behaviour, but
// preferable to catch the drift here first.
describe('error code allowlists', () => {
  it('APP_ERROR_CODES covers every variant in the test sweep', () => {
    const sweepCodes: AppError['code'][] = [
      'vault_path_not_found',
      'vault_path_not_a_vault',
      'vault_path_locked',
      'wrong_password',
      'kdf_too_weak',
      'vault_corrupt',
      'already_unlocked',
      'not_unlocked',
      'settings_corrupt',
      'settings_unknown_version',
      'settings_out_of_range',
      'io',
      'block_not_found',
      'record_not_found',
      'field_not_found',
      'invalid_field_value',
      'record_save_failed',
      'vault_folder_not_empty',
      'vault_create_failed',
      'internal'
    ];
    expect([...APP_ERROR_CODES].sort()).toEqual([...sweepCodes].sort());
  });

  it('APP_WARNING_CODES covers every warning variant', () => {
    const sweepCodes: AppWarning['code'][] = [
      'settings_corrupt',
      'settings_clamped',
      'settings_unknown_version'
    ];
    expect([...APP_WARNING_CODES].sort()).toEqual([...sweepCodes].sort());
  });
});
