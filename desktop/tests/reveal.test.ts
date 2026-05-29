import { describe, it, expect, vi } from 'vitest';
import { createAutoHideTimer } from '../src/lib/reveal';

describe('createAutoHideTimer', () => {
  it('fires the callback after the delay', () => {
    vi.useFakeTimers();
    const cb = vi.fn();
    const timer = createAutoHideTimer(cb, 20_000);
    timer.start();
    expect(cb).not.toHaveBeenCalled();
    vi.advanceTimersByTime(20_000);
    expect(cb).toHaveBeenCalledOnce();
    vi.useRealTimers();
  });

  it('cancel prevents the callback', () => {
    vi.useFakeTimers();
    const cb = vi.fn();
    const timer = createAutoHideTimer(cb, 20_000);
    timer.start();
    timer.cancel();
    vi.advanceTimersByTime(20_000);
    expect(cb).not.toHaveBeenCalled();
    vi.useRealTimers();
  });

  it('start resets a pending timer (debounce)', () => {
    vi.useFakeTimers();
    const cb = vi.fn();
    const timer = createAutoHideTimer(cb, 20_000);
    timer.start();
    vi.advanceTimersByTime(15_000);
    timer.start();
    vi.advanceTimersByTime(15_000);
    expect(cb).not.toHaveBeenCalled();
    vi.advanceTimersByTime(5_000);
    expect(cb).toHaveBeenCalledOnce();
    vi.useRealTimers();
  });
});
