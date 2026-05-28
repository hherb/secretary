// Pins the frontend ↔ Rust constants contract. Values themselves are
// duplicated across the wire (no IPC carries constants); these tests
// don't exhaustively re-prove arithmetic but DO encode the structural
// invariants that catch drift bugs — bounds must be sensibly ordered,
// minute conversion must round-trip cleanly, and the default must lie
// strictly inside the bounds so the SettingsDialog's pre-populated
// value never lands on an out-of-range value.

import { describe, it, expect } from 'vitest';
import {
  MS_PER_MINUTE,
  AUTO_LOCK_MIN_MS,
  AUTO_LOCK_MAX_MS,
  AUTO_LOCK_DEFAULT_MS
} from '../src/lib/constants';

describe('constants — auto-lock bounds invariants', () => {
  it('MS_PER_MINUTE equals 60 seconds × 1000 ms (arithmetic sanity)', () => {
    expect(MS_PER_MINUTE).toBe(60 * 1000);
  });

  it('min < default < max — defaults must lie strictly inside the bounds', () => {
    // Without this, a future refactor that nudges the default outside the
    // bounds would let SettingsDialog open with a value its own validator
    // immediately rejects on Save.
    expect(AUTO_LOCK_MIN_MS).toBeLessThan(AUTO_LOCK_DEFAULT_MS);
    expect(AUTO_LOCK_DEFAULT_MS).toBeLessThan(AUTO_LOCK_MAX_MS);
  });

  it('bounds are whole-minute multiples — UI works in minutes', () => {
    // SettingsDialog presents the input as integer minutes. If a bound
    // weren't a whole-minute multiple, the dialog could clamp to a
    // displayed value that's actually out of range on the wire.
    expect(AUTO_LOCK_MIN_MS % MS_PER_MINUTE).toBe(0);
    expect(AUTO_LOCK_MAX_MS % MS_PER_MINUTE).toBe(0);
    expect(AUTO_LOCK_DEFAULT_MS % MS_PER_MINUTE).toBe(0);
  });

  it('all bounds are positive — auto-lock can never be 0 or negative ms', () => {
    expect(AUTO_LOCK_MIN_MS).toBeGreaterThan(0);
    expect(AUTO_LOCK_MAX_MS).toBeGreaterThan(0);
    expect(AUTO_LOCK_DEFAULT_MS).toBeGreaterThan(0);
  });
});
