// Svelte stores for session-level state. Components subscribe via
// `$sessionState` reactivity; non-Svelte modules use the imperative
// `.subscribe()` / `.update()` surface.
//
// The discriminated union encodes UI states (not just unlock/lock booleans)
// so the App.svelte router can `switch ($s.status)` instead of branching
// on bag-of-booleans. `lastError` is null except in the locked state — the
// error toast is only meaningful when we landed back on the unlock screen.

import { writable, derived } from 'svelte/store';
import type { AppError } from './errors';
import type { ManifestDto, SettingsDto } from './ipc';

export type SessionState =
  | { status: 'locked'; lastError: AppError | null }
  | { status: 'unlocking' }
  | { status: 'unlocked'; manifest: ManifestDto; settings: SettingsDto }
  | { status: 'locking' };

export const sessionState = writable<SessionState>({ status: 'locked', lastError: null });

// Short-lived notice surfaced when the auto-lock timer fires (`idle`),
// the user clicks Lock (`manual`), or the activity-tracker keep-alive
// IPC starts failing (`keep_alive_failing`). The discriminated union
// lets the toast component pick its copy and severity based on `reason`
// rather than parsing a free-form string. `at` is the millisecond
// timestamp when the notice was raised, used for de-duplication and
// auto-dismiss timing.
export type AutoLockNotice =
  | { reason: 'idle'; at: number }
  | { reason: 'manual'; at: number }
  | { reason: 'keep_alive_failing'; at: number };

export const autoLockNotice = writable<AutoLockNotice | null>(null);

// Convenience selector — null whenever the session is not unlocked.
export const currentSettings = derived(sessionState, ($s) =>
  $s.status === 'unlocked' ? $s.settings : null
);
