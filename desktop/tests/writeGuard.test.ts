import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  authorizeWrite,
  resetReauthGuard,
  seedReauthClock,
  ReauthCancelled,
  __setWriteGuardTestSeam,
  type WriteGuardSeam
} from '../src/lib/writeGuard';
import type { PresenceOutcome } from '../src/lib/presence';

// A controllable settings source + clock + prompt driver (design B).
// The seam has NO verify — the dialog owns verification; the guard only
// calls prompt() and treats resolve as "authorized" / reject as "cancelled".
//
// `biometricPrefEnabled` defaults to `() => false` so these pre-#277 tests
// exercise the password-only path unchanged: `authorizeWrite` skips
// `tryBiometric` entirely and goes straight to `prompt`. Tests that need
// the biometric pre-step use `biometricSeam` below instead.
function installSeam(opts: {
  enabled: boolean;
  windowMs: number;
  now: () => number;
  prompt: (reason: string) => Promise<void>;
  biometricPrefEnabled?: () => boolean;
  tryBiometric?: (reason: string) => Promise<PresenceOutcome>;
}) {
  __setWriteGuardTestSeam({
    readSettings: () => ({ enabled: opts.enabled, windowMs: opts.windowMs }),
    now: opts.now,
    prompt: opts.prompt,
    biometricPrefEnabled: opts.biometricPrefEnabled ?? (() => false),
    tryBiometric: opts.tryBiometric ?? (async () => 'unavailable')
  });
}

// Seam builder for the biometric pre-step tests: defaults to pref-ON +
// an immediate 'authenticated' outcome + a grace window of 0 (always needs
// reauth), so each test only needs to override what it's exercising.
function biometricSeam(overrides: Partial<WriteGuardSeam> = {}): WriteGuardSeam {
  return {
    readSettings: () => ({ enabled: true, windowMs: 0 }),
    now: () => 1000,
    prompt: vi.fn(async () => {}),
    biometricPrefEnabled: () => true,
    tryBiometric: vi.fn(async () => 'authenticated' as const),
    ...overrides
  };
}

beforeEach(() => resetReauthGuard());

describe('authorizeWrite', () => {
  it('resolves without prompting when disabled', async () => {
    const prompt = vi.fn((_reason: string): Promise<void> => Promise.resolve());
    installSeam({ enabled: false, windowMs: 1000, now: () => 0, prompt });
    await authorizeWrite('Confirm deleting this entry');
    expect(prompt).not.toHaveBeenCalled();
  });

  it('prompts once when enabled and never authed; second call within window skips prompt; past window prompts again', async () => {
    let t = 1000;
    const prompt = vi.fn((_reason: string): Promise<void> => Promise.resolve());
    installSeam({ enabled: true, windowMs: 1000, now: () => t, prompt });

    // First call: within-window clock is 1000, never authed → must prompt.
    await authorizeWrite('Confirm saving this entry');
    expect(prompt).toHaveBeenCalledTimes(1);

    // Immediately again at t=1500 — inside the 1000ms window → no prompt.
    t = 1500;
    await authorizeWrite('Confirm saving this entry');
    expect(prompt).toHaveBeenCalledTimes(1);

    // Past the window (t=2000, lastAuthAt=1000, elapsed=1000 >= window=1000) → prompt again.
    t = 2000;
    await authorizeWrite('Confirm saving this entry');
    expect(prompt).toHaveBeenCalledTimes(2);
  });

  it('rejects with ReauthCancelled on cancel and does not advance the clock', async () => {
    const prompt = vi.fn((_reason: string): Promise<void> => Promise.reject(ReauthCancelled));
    installSeam({ enabled: true, windowMs: 1000, now: () => 5000, prompt });

    await expect(authorizeWrite('Confirm moving this entry')).rejects.toBe(ReauthCancelled);

    // Clock NOT advanced — next call must still prompt.
    prompt.mockResolvedValueOnce(undefined);
    await authorizeWrite('Confirm moving this entry');
    expect(prompt).toHaveBeenCalledTimes(2);
  });
});

describe('authorizeWrite biometric pre-step', () => {
  beforeEach(() => resetReauthGuard());

  it('biometric authenticated → no password prompt, resolves', async () => {
    const s = biometricSeam();
    __setWriteGuardTestSeam(s);
    await authorizeWrite('reason');
    expect(s.tryBiometric).toHaveBeenCalledOnce();
    expect(s.prompt).not.toHaveBeenCalled();
  });

  it('biometric fallback → opens password prompt', async () => {
    const s = biometricSeam({ tryBiometric: vi.fn(async () => 'fallback' as const) });
    __setWriteGuardTestSeam(s);
    await authorizeWrite('reason');
    expect(s.prompt).toHaveBeenCalledOnce();
  });

  it('biometric unavailable → opens password prompt', async () => {
    const s = biometricSeam({ tryBiometric: vi.fn(async () => 'unavailable' as const) });
    __setWriteGuardTestSeam(s);
    await authorizeWrite('reason');
    expect(s.prompt).toHaveBeenCalledOnce();
  });

  it('biometric cancelled → rejects with ReauthCancelled, no prompt', async () => {
    const s = biometricSeam({ tryBiometric: vi.fn(async () => 'cancelled' as const) });
    __setWriteGuardTestSeam(s);
    await expect(authorizeWrite('reason')).rejects.toBe(ReauthCancelled);
    expect(s.prompt).not.toHaveBeenCalled();
  });

  it('pref disabled → skips biometry, goes straight to password', async () => {
    const s = biometricSeam({ biometricPrefEnabled: () => false, tryBiometric: vi.fn() });
    __setWriteGuardTestSeam(s);
    await authorizeWrite('reason');
    expect(s.tryBiometric).not.toHaveBeenCalled();
    expect(s.prompt).toHaveBeenCalledOnce();
  });

  it('within grace window → neither biometry nor prompt', async () => {
    const s = biometricSeam({ readSettings: () => ({ enabled: true, windowMs: 60_000 }) });
    __setWriteGuardTestSeam(s);
    seedReauthClock(1000); // now() === 1000, so 0 elapsed < window
    await authorizeWrite('reason');
    expect(s.tryBiometric).not.toHaveBeenCalled();
    expect(s.prompt).not.toHaveBeenCalled();
  });
});
