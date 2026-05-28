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

// Short-lived notice surfaced when the auto-lock timer fires (vs explicit
// user-initiated lock). Toast component reads + clears on a timeout.
export const autoLockNotice = writable<string | null>(null);

// Convenience selector — null whenever the session is not unlocked.
export const currentSettings = derived(sessionState, ($s) =>
  $s.status === 'unlocked' ? $s.settings : null
);
