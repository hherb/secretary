// Pins the rate-limit + cleanup contract for startActivityTracking().

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { get } from 'svelte/store';

const { notifyActivityMock } = vi.hoisted(() => ({ notifyActivityMock: vi.fn() }));

vi.mock('../src/lib/ipc', () => ({
  notifyActivity: notifyActivityMock
}));

import {
  startActivityTracking,
  _resetActivityTrackingForTest,
  ACTIVITY_NOTIFY_MIN_INTERVAL_MS
} from '../src/lib/auto_lock';
import { autoLockNotice } from '../src/lib/stores';

beforeEach(() => {
  vi.useFakeTimers();
  notifyActivityMock.mockReset();
  notifyActivityMock.mockResolvedValue(undefined);
  _resetActivityTrackingForTest();
  autoLockNotice.set(null);
  // Suppress the warn breadcrumb from the failure path; tests that
  // assert on it re-spy with their own implementation.
  vi.spyOn(console, 'warn').mockImplementation(() => {});
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('startActivityTracking', () => {
  it('first mousemove triggers immediate notifyActivity', () => {
    startActivityTracking();
    document.dispatchEvent(new MouseEvent('mousemove'));
    expect(notifyActivityMock).toHaveBeenCalledTimes(1);
  });

  it('first keydown triggers immediate notifyActivity', () => {
    startActivityTracking();
    document.dispatchEvent(new KeyboardEvent('keydown'));
    expect(notifyActivityMock).toHaveBeenCalledTimes(1);
  });

  it('subsequent events within debounce window do not re-trigger immediately', () => {
    startActivityTracking();
    document.dispatchEvent(new MouseEvent('mousemove'));
    document.dispatchEvent(new KeyboardEvent('keydown'));
    document.dispatchEvent(new MouseEvent('mousemove'));
    expect(notifyActivityMock).toHaveBeenCalledTimes(1);
  });

  it('event after debounce window triggers a new notify', () => {
    startActivityTracking();
    document.dispatchEvent(new MouseEvent('mousemove'));
    vi.advanceTimersByTime(ACTIVITY_NOTIFY_MIN_INTERVAL_MS + 1);
    document.dispatchEvent(new MouseEvent('mousemove'));
    expect(notifyActivityMock).toHaveBeenCalledTimes(2);
  });

  it('debounced trailing event fires via setTimeout when window expires', () => {
    startActivityTracking();
    document.dispatchEvent(new MouseEvent('mousemove'));
    document.dispatchEvent(new MouseEvent('mousemove'));
    expect(notifyActivityMock).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(ACTIVITY_NOTIFY_MIN_INTERVAL_MS + 1);
    expect(notifyActivityMock).toHaveBeenCalledTimes(2);
  });

  it('cleanup detaches listeners — no further notifies on dispatched events', () => {
    const cleanupFn = startActivityTracking();
    cleanupFn();
    document.dispatchEvent(new MouseEvent('mousemove'));
    document.dispatchEvent(new KeyboardEvent('keydown'));
    expect(notifyActivityMock).not.toHaveBeenCalled();
  });

  it('cleanup cancels a pending debounce timer', () => {
    const cleanupFn = startActivityTracking();
    document.dispatchEvent(new MouseEvent('mousemove'));
    document.dispatchEvent(new MouseEvent('mousemove'));
    expect(notifyActivityMock).toHaveBeenCalledTimes(1);
    cleanupFn();
    vi.advanceTimersByTime(ACTIVITY_NOTIFY_MIN_INTERVAL_MS * 2);
    expect(notifyActivityMock).toHaveBeenCalledTimes(1);
  });

  it('starting twice tears down the prior installation', () => {
    startActivityTracking();
    startActivityTracking();
    document.dispatchEvent(new MouseEvent('mousemove'));
    expect(notifyActivityMock).toHaveBeenCalledTimes(1);
  });

  it('debounce window does not re-arm under a flood — exactly two notifies for a flood that crosses the window', async () => {
    // Five mousemoves inside the window should yield one immediate
    // notify (leading) + one trailing notify (scheduled on the first
    // burst-after-leading event). A refactor that re-armed the timer on
    // every burst event would yield more than two.
    startActivityTracking();
    for (let i = 0; i < 5; i++) {
      document.dispatchEvent(new MouseEvent('mousemove'));
    }
    expect(notifyActivityMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(ACTIVITY_NOTIFY_MIN_INTERVAL_MS + 1);
    expect(notifyActivityMock).toHaveBeenCalledTimes(2);
  });
});

describe('notifyActivity failure handling', () => {
  it('single notifyActivity rejection logs warn but does not raise the toast', async () => {
    const warnSpy = vi.spyOn(console, 'warn').mockImplementation(() => {});
    notifyActivityMock.mockRejectedValueOnce(new Error('locked'));
    startActivityTracking();
    document.dispatchEvent(new MouseEvent('mousemove'));
    // Flush the rejected promise's microtask before asserting.
    await Promise.resolve();
    await Promise.resolve();
    expect(warnSpy).toHaveBeenCalled();
    expect(get(autoLockNotice)).toBeNull();
  });

  it('two consecutive rejections raise the keep_alive_failing toast', async () => {
    notifyActivityMock.mockRejectedValue(new Error('locked'));
    startActivityTracking();
    document.dispatchEvent(new MouseEvent('mousemove'));
    await Promise.resolve();
    await Promise.resolve();
    expect(get(autoLockNotice)).toBeNull();

    // Second leading-edge call after the debounce window expires.
    await vi.advanceTimersByTimeAsync(ACTIVITY_NOTIFY_MIN_INTERVAL_MS + 1);
    document.dispatchEvent(new MouseEvent('mousemove'));
    await Promise.resolve();
    await Promise.resolve();

    const notice = get(autoLockNotice);
    expect(notice).not.toBeNull();
    expect(notice?.reason).toBe('keep_alive_failing');
    expect(typeof notice?.at).toBe('number');
  });

  it('a successful notify resets the consecutive-failure counter', async () => {
    notifyActivityMock.mockRejectedValueOnce(new Error('transient'));
    startActivityTracking();
    document.dispatchEvent(new MouseEvent('mousemove'));
    await Promise.resolve();
    await Promise.resolve();

    // Next notify succeeds — counter should reset.
    notifyActivityMock.mockResolvedValueOnce(undefined);
    await vi.advanceTimersByTimeAsync(ACTIVITY_NOTIFY_MIN_INTERVAL_MS + 1);
    document.dispatchEvent(new MouseEvent('mousemove'));
    await Promise.resolve();
    await Promise.resolve();

    // A single fresh failure after the reset must not immediately raise
    // the toast (would need two consecutive failures).
    notifyActivityMock.mockRejectedValueOnce(new Error('transient2'));
    await vi.advanceTimersByTimeAsync(ACTIVITY_NOTIFY_MIN_INTERVAL_MS + 1);
    document.dispatchEvent(new MouseEvent('mousemove'));
    await Promise.resolve();
    await Promise.resolve();

    expect(get(autoLockNotice)).toBeNull();
  });
});
