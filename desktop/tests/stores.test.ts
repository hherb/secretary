// Pins the SessionState transition contract and the derived stores.
//
// PR #148 shipped `SessionState` as a raw `writable<SessionState>` exported
// directly to consumers. Issue #150 closed in this PR demotes the writable
// to a non-exported `_internal` and exposes only legal-transition helpers
// (`beginUnlock`, `unlockSucceeded`, `unlockFailed`, `beginLock`,
// `vaultLocked`) plus a read-only subscription view. Illegal edges throw
// in dev (Vitest runs in dev mode, so the tests below catch them); prod
// builds log + no-op so a frontend state-machine bug never DOS's the user.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { get } from 'svelte/store';
import {
  sessionState,
  currentSettings,
  autoLockNotice,
  beginUnlock,
  unlockSucceeded,
  unlockFailed,
  beginLock,
  lockFailed,
  vaultLocked,
  settingsUpdated,
  _resetSessionStateForTest,
  type SessionState
} from '../src/lib/stores';
import type { ManifestDto, SettingsDto } from '../src/lib/ipc';
import type { AppError } from '../src/lib/errors';

const MANIFEST: ManifestDto = {
  vaultUuidHex: 'aa',
  ownerUserUuidHex: 'bb',
  blockCount: 0,
  blockSummaries: [],
  warnings: []
};
const SETTINGS: SettingsDto = {
  autoLockTimeoutMs: 600_000,
  requirePasswordBeforeEdits: false,
  reauthGraceWindowMs: 120_000
};
const WRONG_PWD: AppError = { code: 'wrong_password' };
const INTERNAL_ERR: AppError = { code: 'internal' };

beforeEach(() => {
  _resetSessionStateForTest();
});

describe('sessionState initial shape', () => {
  it('starts in locked with no lastError', () => {
    const s = get(sessionState);
    expect(s.status).toBe('locked');
    if (s.status === 'locked') {
      expect(s.lastError).toBeNull();
    }
  });

  it('exposes a read-only subscription surface (no .set method)', () => {
    // Demotion check: a runtime `set` on the public store would indicate
    // the demotion was undone and consumers can bypass transition rules.
    expect((sessionState as unknown as { set?: unknown }).set).toBeUndefined();
  });
});

describe('legal transitions', () => {
  it('locked → unlocking via beginUnlock (carries startedAt)', () => {
    beginUnlock(12_345);
    const s = get(sessionState);
    expect(s.status).toBe('unlocking');
    if (s.status === 'unlocking') {
      expect(s.startedAt).toBe(12_345);
    }
  });

  it('beginUnlock defaults startedAt to Date.now() when omitted', () => {
    const before = Date.now();
    beginUnlock();
    const after = Date.now();
    const s = get(sessionState);
    if (s.status === 'unlocking') {
      expect(s.startedAt).toBeGreaterThanOrEqual(before);
      expect(s.startedAt).toBeLessThanOrEqual(after);
    } else {
      throw new Error('expected unlocking');
    }
  });

  it('unlocking → unlocked via unlockSucceeded', () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    const s = get(sessionState);
    expect(s.status).toBe('unlocked');
    if (s.status === 'unlocked') {
      expect(s.manifest).toEqual(MANIFEST);
      expect(s.settings).toEqual(SETTINGS);
    }
  });

  it('unlocking → locked via unlockFailed (carries the error)', () => {
    beginUnlock(0);
    unlockFailed(WRONG_PWD);
    const s = get(sessionState);
    expect(s.status).toBe('locked');
    if (s.status === 'locked') {
      expect(s.lastError).toEqual(WRONG_PWD);
    }
  });

  it('unlocked → locking via beginLock (carries startedAt)', () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    beginLock(54_321);
    const s = get(sessionState);
    expect(s.status).toBe('locking');
    if (s.status === 'locking') {
      expect(s.startedAt).toBe(54_321);
    }
  });

  it('locking → locked via vaultLocked', () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    beginLock(0);
    vaultLocked('manual', 0);
    const s = get(sessionState);
    expect(s.status).toBe('locked');
    if (s.status === 'locked') {
      expect(s.lastError).toBeNull();
    }
  });

  it('unlocked → unlocked via settingsUpdated (settings field replaced, manifest preserved)', () => {
    // SettingsDialog calls `settingsUpdated(newSettings)` after a successful
    // `set_settings` IPC so the in-memory store reflects the persisted value
    // immediately (no round-trip through `getSettings`). The transition is
    // intentionally settings-only — the manifest stays referentially equal
    // so downstream `$derived` selectors keyed on it don't churn.
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    const before = get(sessionState);
    const beforeManifest = before.status === 'unlocked' ? before.manifest : null;
    const newSettings: SettingsDto = { autoLockTimeoutMs: 300_000, requirePasswordBeforeEdits: true, reauthGraceWindowMs: 60_000 };
    settingsUpdated(newSettings);
    const after = get(sessionState);
    expect(after.status).toBe('unlocked');
    if (after.status === 'unlocked') {
      expect(after.settings).toEqual(newSettings);
      // Manifest reference preserved — same object identity, not a clone.
      expect(after.manifest).toBe(beforeManifest);
    }
  });

  it('locking → locked via lockFailed (carries the error)', () => {
    // Lock IPC is documented infallible per spec §7, but transport-level
    // errors (mutex poison, event-emit failure) can still surface from the
    // Tauri layer. Without `lockFailed`, the `locking` state would stick
    // until the next backend `vault-locked` event — bad UX. `lockFailed`
    // transitions to `locked` and captures the typed error so the user
    // sees something happened and can retry.
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    beginLock(0);
    lockFailed(INTERNAL_ERR);
    const s = get(sessionState);
    expect(s.status).toBe('locked');
    if (s.status === 'locked') {
      expect(s.lastError).toEqual(INTERNAL_ERR);
    }
  });
});

describe('error narrowing — lockFailed / unlockFailed accept unknown', () => {
  // `lockFailed` / `unlockFailed` are typed `(err: unknown) => void` and
  // narrow internally via `isAppError`. Belt-and-braces against the
  // (currently impossible) case of `call()` in ipc.ts leaking a non-
  // AppError rejection: the helpers must coerce to `{ code: 'internal' }`
  // rather than dropping a malformed payload into `lastError` where
  // `userMessageFor` would have to render an unknown discriminant.

  let errorSpy: ReturnType<typeof vi.spyOn>;
  beforeEach(() => {
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => {
    errorSpy.mockRestore();
  });

  it('lockFailed coerces a bare-string rejection to { code: "internal" }', () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    beginLock(0);
    lockFailed('something exploded');
    const s = get(sessionState);
    expect(s.status).toBe('locked');
    if (s.status === 'locked') {
      expect(s.lastError).toEqual({ code: 'internal' });
    }
    expect(errorSpy).toHaveBeenCalled();
  });

  it('lockFailed coerces a plain Error to { code: "internal" }', () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    beginLock(0);
    lockFailed(new Error('panic from Tauri runtime'));
    const s = get(sessionState);
    if (s.status === 'locked') {
      expect(s.lastError).toEqual({ code: 'internal' });
    }
  });

  it('lockFailed coerces a future-unknown { code } shape to { code: "internal" }', () => {
    // Simulates a future Rust AppError variant whose discriminator the
    // TS union doesn't know yet. The helper falls back to `internal`
    // rather than letting an unrenderable discriminant reach the UI.
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    beginLock(0);
    lockFailed({ code: 'future_variant_not_yet_in_ts_union' });
    const s = get(sessionState);
    if (s.status === 'locked') {
      expect(s.lastError).toEqual({ code: 'internal' });
    }
  });

  it('lockFailed passes through a real typed AppError unchanged', () => {
    // Regression pin: narrowing must NOT clobber a valid AppError.
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    beginLock(0);
    lockFailed(WRONG_PWD);
    const s = get(sessionState);
    if (s.status === 'locked') {
      expect(s.lastError).toEqual(WRONG_PWD);
    }
  });

  it('unlockFailed coerces a bare-string rejection to { code: "internal" }', () => {
    beginUnlock(0);
    unlockFailed('something exploded');
    const s = get(sessionState);
    expect(s.status).toBe('locked');
    if (s.status === 'locked') {
      expect(s.lastError).toEqual({ code: 'internal' });
    }
  });

  it('unlockFailed passes through a real typed AppError unchanged', () => {
    beginUnlock(0);
    unlockFailed(WRONG_PWD);
    const s = get(sessionState);
    if (s.status === 'locked') {
      expect(s.lastError).toEqual(WRONG_PWD);
    }
  });
});

describe('vaultLocked is authoritative — accepts from any state', () => {
  it('from locked → locked + autoLockNotice fires', () => {
    vaultLocked('idle', 100);
    expect(get(sessionState).status).toBe('locked');
    expect(get(autoLockNotice)).toEqual({ reason: 'idle', at: 100 });
  });

  it('from unlocking → locked', () => {
    beginUnlock(0);
    vaultLocked('idle', 200);
    expect(get(sessionState).status).toBe('locked');
    expect(get(autoLockNotice)).toEqual({ reason: 'idle', at: 200 });
  });

  it('from unlocked → locked', () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    vaultLocked('manual', 300);
    expect(get(sessionState).status).toBe('locked');
    // `manual` does NOT raise the notice — the user clicked Lock
    // themselves, no confirmation surface is needed (filter lives in
    // the producer, see stores.ts::vaultLocked).
    expect(get(autoLockNotice)).toBeNull();
  });

  it('from locking → locked', () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    beginLock(0);
    vaultLocked('manual', 400);
    expect(get(sessionState).status).toBe('locked');
    expect(get(autoLockNotice)).toBeNull();
  });

  it('vaultLocked(\'idle\') raises the autoLockNotice with the carrying timestamp', () => {
    // Pinned separately from the existing "from unlocking → locked"
    // test so the producer-side filter contract is explicit: idle
    // writes, manual does not.
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    vaultLocked('idle', 500);
    expect(get(autoLockNotice)).toEqual({ reason: 'idle', at: 500 });
  });

  it('vaultLocked(\'manual\') does NOT raise the autoLockNotice even when one was already set', () => {
    // Defence in depth: if a prior keep_alive_failing or idle notice
    // sits in the store, a subsequent manual lock must leave it as-is
    // (the manual lock itself doesn't add a new notice). The producer
    // filter is strictly "manual doesn't write", not "manual clears".
    autoLockNotice.set({ reason: 'keep_alive_failing', at: 100 });
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    vaultLocked('manual', 200);
    // Note: unlockSucceeded above cleared the keep_alive_failing
    // notice (the unlock-clears-stale-notice contract). So the
    // post-vaultLocked('manual') state is null. This pins both
    // contracts in one place.
    expect(get(autoLockNotice)).toBeNull();
  });
});

describe('unlockSucceeded clears any stale autoLockNotice', () => {
  // Spec §12 ties the notice to the lock event. A user who returns
  // to an undismissed auto-lock toast and then unlocks shouldn't
  // see the stale notice linger on top of their freshly-mounted
  // Vault while the dismiss timer counts down — the unlock itself
  // is the user-action that should clear the notice.

  it('a pre-existing idle notice is cleared on successful unlock', () => {
    autoLockNotice.set({ reason: 'idle', at: 100 });
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    expect(get(autoLockNotice)).toBeNull();
  });

  it('a pre-existing keep_alive_failing notice is cleared on successful unlock', () => {
    autoLockNotice.set({ reason: 'keep_alive_failing', at: 100 });
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    expect(get(autoLockNotice)).toBeNull();
  });
});

describe('illegal transitions throw in dev', () => {
  // Vitest runs with `import.meta.env.DEV === true`, so the dev-build
  // assertion branch fires. Each variant gets at least one rejection pin
  // so a regression that loosens the contract surfaces immediately.

  it('beginUnlock from unlocking is rejected', () => {
    beginUnlock(0);
    expect(() => beginUnlock(0)).toThrow(/illegal session transition/i);
    expect(get(sessionState).status).toBe('unlocking');
  });

  it('beginUnlock from unlocked is rejected', () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    expect(() => beginUnlock(0)).toThrow(/illegal session transition/i);
    expect(get(sessionState).status).toBe('unlocked');
  });

  it('unlockSucceeded from locked is rejected', () => {
    expect(() => unlockSucceeded(MANIFEST, SETTINGS)).toThrow(/illegal session transition/i);
    expect(get(sessionState).status).toBe('locked');
  });

  it('unlockFailed from unlocked is rejected', () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    expect(() => unlockFailed(WRONG_PWD)).toThrow(/illegal session transition/i);
    expect(get(sessionState).status).toBe('unlocked');
  });

  it('beginLock from locked is rejected', () => {
    expect(() => beginLock(0)).toThrow(/illegal session transition/i);
    expect(get(sessionState).status).toBe('locked');
  });

  it('beginLock from locking is rejected', () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    beginLock(0);
    expect(() => beginLock(0)).toThrow(/illegal session transition/i);
    expect(get(sessionState).status).toBe('locking');
  });

  it('lockFailed from locked is rejected', () => {
    expect(() => lockFailed(INTERNAL_ERR)).toThrow(/illegal session transition/i);
    expect(get(sessionState).status).toBe('locked');
  });

  it('lockFailed from unlocking is rejected', () => {
    beginUnlock(0);
    expect(() => lockFailed(INTERNAL_ERR)).toThrow(/illegal session transition/i);
    expect(get(sessionState).status).toBe('unlocking');
  });

  it('lockFailed from unlocked is rejected', () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    expect(() => lockFailed(INTERNAL_ERR)).toThrow(/illegal session transition/i);
    expect(get(sessionState).status).toBe('unlocked');
  });

  it('settingsUpdated from locked is rejected', () => {
    const newSettings: SettingsDto = { autoLockTimeoutMs: 300_000, requirePasswordBeforeEdits: true, reauthGraceWindowMs: 60_000 };
    expect(() => settingsUpdated(newSettings)).toThrow(/illegal session transition/i);
    expect(get(sessionState).status).toBe('locked');
  });

  it('settingsUpdated from unlocking is rejected', () => {
    const newSettings: SettingsDto = { autoLockTimeoutMs: 300_000, requirePasswordBeforeEdits: true, reauthGraceWindowMs: 60_000 };
    beginUnlock(0);
    expect(() => settingsUpdated(newSettings)).toThrow(/illegal session transition/i);
    expect(get(sessionState).status).toBe('unlocking');
  });

  it('settingsUpdated from locking is rejected', () => {
    const newSettings: SettingsDto = { autoLockTimeoutMs: 300_000, requirePasswordBeforeEdits: true, reauthGraceWindowMs: 60_000 };
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    beginLock(0);
    expect(() => settingsUpdated(newSettings)).toThrow(/illegal session transition/i);
    expect(get(sessionState).status).toBe('locking');
  });
});

describe('illegal transitions log + no-op in prod', () => {
  // Mock `import.meta.env.DEV` to false for these tests. Without this
  // branch the prod-build silent-coerce path goes uncovered and a
  // regression that swallows ALL illegal edges (instead of just the
  // dev throw) would slip through.
  let errorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    vi.stubEnv('DEV', false);
    errorSpy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    errorSpy.mockRestore();
  });

  it('beginUnlock from unlocking logs + leaves state unchanged', () => {
    beginUnlock(0);
    beginUnlock(0); // would-be illegal — must not throw, must log
    expect(errorSpy).toHaveBeenCalledTimes(1);
    expect(get(sessionState).status).toBe('unlocking');
  });
});

describe('SessionState shape exhaustiveness', () => {
  it('every variant in the union is reachable via legal transitions', () => {
    // locked (initial)
    expect(get(sessionState).status).toBe('locked');
    // unlocking
    beginUnlock(0);
    expect(get(sessionState).status).toBe('unlocking');
    // unlocked
    unlockSucceeded(MANIFEST, SETTINGS);
    expect(get(sessionState).status).toBe('unlocked');
    // locking
    beginLock(0);
    expect(get(sessionState).status).toBe('locking');
    // locked (via vaultLocked)
    vaultLocked('manual', 0);
    expect(get(sessionState).status).toBe('locked');
  });
});

describe('currentSettings derived selector', () => {
  it('is null in the locked state', () => {
    expect(get(currentSettings)).toBeNull();
  });

  it('is null in the unlocking state', () => {
    beginUnlock(0);
    expect(get(currentSettings)).toBeNull();
  });

  it('is null in the locking state', () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    beginLock(0);
    expect(get(currentSettings)).toBeNull();
  });

  it('returns the settings object only in the unlocked state', () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    expect(get(currentSettings)).toEqual(SETTINGS);
  });

  it('reverts to null when transitioning unlocked → locked via vaultLocked', () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    expect(get(currentSettings)).not.toBeNull();
    vaultLocked('manual', 0);
    expect(get(currentSettings)).toBeNull();
  });
});

describe('autoLockNotice discriminated union', () => {
  it('starts null', () => {
    expect(get(autoLockNotice)).toBeNull();
  });

  it('keep_alive_failing reason can be set directly (raised by auto_lock.ts, not stores)', () => {
    // The keep_alive_failing notice is owned by auto_lock.ts's retry logic,
    // not by the session-state transitions. The writable's direct set
    // surface stays intentional for that producer.
    const at = 12_345;
    autoLockNotice.set({ reason: 'keep_alive_failing', at });
    expect(get(autoLockNotice)).toEqual({ reason: 'keep_alive_failing', at });
  });

  it('can be cleared back to null', () => {
    autoLockNotice.set({ reason: 'idle', at: 0 });
    autoLockNotice.set(null);
    expect(get(autoLockNotice)).toBeNull();
  });
});

describe('_resetSessionStateForTest', () => {
  it('returns sessionState to initial locked state', () => {
    beginUnlock(0);
    unlockSucceeded(MANIFEST, SETTINGS);
    _resetSessionStateForTest();
    expect(get(sessionState)).toEqual({ status: 'locked', lastError: null });
  });

  it('also clears autoLockNotice', () => {
    autoLockNotice.set({ reason: 'idle', at: 100 });
    _resetSessionStateForTest();
    expect(get(autoLockNotice)).toBeNull();
  });
});

// Re-export of SessionState type stays in scope; ensure the union is
// still narrowable for downstream component code (App.svelte).
describe('SessionState type-narrowing pin', () => {
  it('discriminates on .status', () => {
    const variants: SessionState[] = [
      { status: 'locked', lastError: null },
      { status: 'locked', lastError: { code: 'wrong_password' } },
      { status: 'unlocking', startedAt: 0 },
      { status: 'unlocked', manifest: MANIFEST, settings: SETTINGS },
      { status: 'locking', startedAt: 0 }
    ];
    for (const v of variants) {
      expect(['locked', 'unlocking', 'unlocked', 'locking']).toContain(v.status);
    }
  });
});
