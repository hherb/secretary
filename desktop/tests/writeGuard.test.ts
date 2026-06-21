import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  authorizeWrite,
  resetReauthGuard,
  ReauthCancelled,
  __setWriteGuardTestSeam
} from '../src/lib/writeGuard';

// A controllable settings source + clock + prompt driver (design B).
// The seam has NO verify — the dialog owns verification; the guard only
// calls prompt() and treats resolve as "authorized" / reject as "cancelled".
function installSeam(opts: {
  enabled: boolean;
  windowMs: number;
  now: () => number;
  prompt: (reason: string) => Promise<void>;
}) {
  __setWriteGuardTestSeam({
    readSettings: () => ({ enabled: opts.enabled, windowMs: opts.windowMs }),
    now: opts.now,
    prompt: opts.prompt
  });
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
