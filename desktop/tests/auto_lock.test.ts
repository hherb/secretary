// Pins the rate-limit + cleanup contract for startActivityTracking().
// The mock for ../src/lib/ipc.ts uses vi.hoisted for the same hoisting
// reason as ipc.test.ts.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const { notifyActivityMock } = vi.hoisted(() => ({ notifyActivityMock: vi.fn() }));

vi.mock('../src/lib/ipc', () => ({
  notifyActivity: notifyActivityMock
}));

import {
  startActivityTracking,
  _resetActivityTrackingForTest,
  ACTIVITY_NOTIFY_MIN_INTERVAL_MS
} from '../src/lib/auto_lock';

beforeEach(() => {
  vi.useFakeTimers();
  notifyActivityMock.mockReset();
  notifyActivityMock.mockResolvedValue(undefined);
  _resetActivityTrackingForTest();
});

afterEach(() => {
  vi.useRealTimers();
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
});
