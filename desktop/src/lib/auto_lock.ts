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

// Must match Rust-side ACTIVITY_NOTIFY_MIN_INTERVAL_MS in
// src-tauri/src/constants.rs. Changing one without the other breaks the
// design intent — the Rust clock would still receive every event at a
// faster cadence than expected.
export const ACTIVITY_NOTIFY_MIN_INTERVAL_MS = 2_000;

let lastNotifyMs = 0;
let timerId: ReturnType<typeof setTimeout> | null = null;
let cleanup: (() => void) | null = null;

function maybeNotify(): void {
  const now = Date.now();
  const elapsed = now - lastNotifyMs;
  if (elapsed >= ACTIVITY_NOTIFY_MIN_INTERVAL_MS) {
    lastNotifyMs = now;
    notifyActivity().catch((e) => {
      // Best-effort. A failure (e.g. session locked between the debounce
      // and the IPC call) is silently dropped — the Rust side has the
      // authoritative state and a missed notify just means the next
      // mousemove will retry.
      console.debug('notifyActivity failed', e);
    });
    return;
  }
  if (timerId === null) {
    timerId = setTimeout(() => {
      timerId = null;
      lastNotifyMs = Date.now();
      notifyActivity().catch(() => {});
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
  lastNotifyMs = 0;
  if (timerId !== null) {
    clearTimeout(timerId);
    timerId = null;
  }
  if (cleanup) {
    cleanup();
  }
}
