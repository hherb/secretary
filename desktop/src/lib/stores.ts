// Svelte stores for session-level state. The discriminated union lets
// consumers exhaust on `.status` rather than juggle booleans, and the
// per-variant payloads make illegal states (e.g. reading `manifest`
// while `locked`) unrepresentable at the type level.

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
