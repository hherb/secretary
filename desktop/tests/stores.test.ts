// Pins the SessionState transitions, the `currentSettings` derived store,
// and the AutoLockNotice discriminated union. No consumer (App.svelte
// Task 7+) wires the stores yet, so behaviour-level tests here are the
// only gate that regressions to the state encoding surface immediately.

import { describe, it, expect, beforeEach } from 'vitest';
import { get } from 'svelte/store';
import {
  sessionState,
  currentSettings,
  autoLockNotice,
  type SessionState
} from '../src/lib/stores';

beforeEach(() => {
  sessionState.set({ status: 'locked', lastError: null });
  autoLockNotice.set(null);
});

describe('sessionState initial shape', () => {
  it('starts in locked with no lastError', () => {
    const s = get(sessionState);
    expect(s.status).toBe('locked');
    if (s.status === 'locked') {
      expect(s.lastError).toBeNull();
    }
  });
});

describe('currentSettings derived selector', () => {
  it('is null in the locked state', () => {
    sessionState.set({ status: 'locked', lastError: null });
    expect(get(currentSettings)).toBeNull();
  });

  it('is null in the unlocking state', () => {
    sessionState.set({ status: 'unlocking' });
    expect(get(currentSettings)).toBeNull();
  });

  it('is null in the locking state', () => {
    sessionState.set({ status: 'locking' });
    expect(get(currentSettings)).toBeNull();
  });

  it('returns the settings object only in the unlocked state', () => {
    const settings = { autoLockTimeoutMs: 600_000 };
    const manifest = {
      vaultUuidHex: 'aa',
      ownerUserUuidHex: 'bb',
      blockCount: 0,
      blockSummaries: [],
      warnings: []
    };
    sessionState.set({ status: 'unlocked', manifest, settings });
    expect(get(currentSettings)).toEqual(settings);
  });

  it('reverts to null when transitioning unlocked → locked', () => {
    const settings = { autoLockTimeoutMs: 600_000 };
    const manifest = {
      vaultUuidHex: 'aa',
      ownerUserUuidHex: 'bb',
      blockCount: 0,
      blockSummaries: [],
      warnings: []
    };
    sessionState.set({ status: 'unlocked', manifest, settings });
    expect(get(currentSettings)).not.toBeNull();
    sessionState.set({ status: 'locked', lastError: { code: 'wrong_password' } });
    expect(get(currentSettings)).toBeNull();
  });
});

describe('SessionState shape exhaustiveness', () => {
  // Verify each declared variant constructs cleanly and the type-narrowing
  // switch in consumers (App.svelte's router will be the next caller) can
  // discriminate on `.status` without runtime surprises.
  it('every variant in the union is constructible and discriminable', () => {
    const variants: SessionState[] = [
      { status: 'locked', lastError: null },
      { status: 'locked', lastError: { code: 'wrong_password' } },
      { status: 'unlocking' },
      {
        status: 'unlocked',
        manifest: {
          vaultUuidHex: 'aa',
          ownerUserUuidHex: 'bb',
          blockCount: 0,
          blockSummaries: [],
          warnings: []
        },
        settings: { autoLockTimeoutMs: 600_000 }
      },
      { status: 'locking' }
    ];
    for (const v of variants) {
      sessionState.set(v);
      expect(get(sessionState).status).toBe(v.status);
    }
  });
});

describe('autoLockNotice discriminated union', () => {
  it('starts null', () => {
    expect(get(autoLockNotice)).toBeNull();
  });

  it('accepts each reason variant', () => {
    const reasons = ['idle', 'manual', 'keep_alive_failing'] as const;
    for (const reason of reasons) {
      const at = Date.now();
      autoLockNotice.set({ reason, at });
      expect(get(autoLockNotice)).toEqual({ reason, at });
    }
  });

  it('can be cleared back to null', () => {
    autoLockNotice.set({ reason: 'idle', at: 0 });
    autoLockNotice.set(null);
    expect(get(autoLockNotice)).toBeNull();
  });
});
