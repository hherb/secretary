// Browser-side activity tracker. Installs document-level mousemove +
// keydown listeners and rate-limits calls to ipc.notifyActivity() to at
// most one per ACTIVITY_NOTIFY_MIN_INTERVAL_MS. The Rust side has the
// authoritative idle clock (src-tauri/src/auto_lock.rs); this module
// exists only to feed it activity signals without overwhelming the IPC
// boundary on every mousemove.
//
// Why a free-standing module (not a Svelte action): the listener target
// is `document`, not a Svelte-mounted element, so component lifecycle
// isn't the natural binding point. App.svelte calls startActivityTracking
// once at mount and the returned cleanup runs on unmount.

import { notifyActivity } from './ipc';
import { autoLockNotice } from './stores';

// Must match Rust-side ACTIVITY_NOTIFY_MIN_INTERVAL_MS in
// src-tauri/src/constants.rs. Changing one without the other breaks the
// design intent — the Rust clock would still receive every event at a
// faster cadence than expected.
export const ACTIVITY_NOTIFY_MIN_INTERVAL_MS = 2_000;

// After this many consecutive notifyActivity() rejections, surface a
// `keep_alive_failing` toast so the user has some signal that the vault
// may auto-lock unexpectedly. Two failures filters one-off transient
// errors (e.g. the user clicked Lock between the debounce and the IPC)
// without burying a sustained failure.
const KEEP_ALIVE_FAILURE_NOTICE_THRESHOLD = 2;

let lastNotifyMs = 0;
let timerId: ReturnType<typeof setTimeout> | null = null;
let cleanup: (() => void) | null = null;
let consecutiveNotifyFailures = 0;

function recordNotifyOutcome(promise: Promise<void>): void {
  promise.then(
    () => {
      consecutiveNotifyFailures = 0;
    },
    (e: unknown) => {
      consecutiveNotifyFailures += 1;
      // `warn` (not `debug`) so the breadcrumb survives default browser
      // log-level filtering — a silent drop here is exactly the failure
      // mode that would let the vault auto-lock unexpectedly.
      console.warn(
        `notifyActivity failed (consecutive=${consecutiveNotifyFailures})`,
        e
      );
      if (consecutiveNotifyFailures >= KEEP_ALIVE_FAILURE_NOTICE_THRESHOLD) {
        autoLockNotice.set({ reason: 'keep_alive_failing', at: Date.now() });
      }
    }
  );
}

function maybeNotify(): void {
  const now = Date.now();
  const elapsed = now - lastNotifyMs;
  if (elapsed >= ACTIVITY_NOTIFY_MIN_INTERVAL_MS) {
    lastNotifyMs = now;
    recordNotifyOutcome(notifyActivity());
    return;
  }
  if (timerId === null) {
    timerId = setTimeout(() => {
      timerId = null;
      lastNotifyMs = Date.now();
      recordNotifyOutcome(notifyActivity());
    }, ACTIVITY_NOTIFY_MIN_INTERVAL_MS - elapsed);
  }
}

/// Install document-level mousemove + keydown listeners. Returns a cleanup
/// function — call it on unmount to detach the listeners and clear any
/// pending timeout. Calling startActivityTracking twice is safe: the
/// previous installation is torn down first.
export function startActivityTracking(): () => void {
  if (cleanup) {
    cleanup();
  }
  document.addEventListener('mousemove', maybeNotify, { passive: true });
  document.addEventListener('keydown', maybeNotify, { passive: true });
  const installed = () => {
    document.removeEventListener('mousemove', maybeNotify);
    document.removeEventListener('keydown', maybeNotify);
    if (timerId !== null) {
      clearTimeout(timerId);
      timerId = null;
    }
    cleanup = null;
  };
  cleanup = installed;
  return installed;
}

// Test-only — resets module-scope state between Vitest cases so each test
// starts from a known baseline (`lastNotifyMs = 0`, no scheduled timer,
// no installed listeners). Underscore-prefixed and `_for_test`-style
// suffix to flag it as not part of the production API.
export function _resetActivityTrackingForTest(): void {
  if (cleanup) {
    cleanup();
  }
  lastNotifyMs = 0;
  consecutiveNotifyFailures = 0;
}
