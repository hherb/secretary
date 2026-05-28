// Session-level Svelte stores with a state-machine API.
//
// The raw `writable<SessionState>` lives as the non-exported `_internal`;
// the public surface is the readable `sessionState` plus a small set of
// transition helpers that enforce the legal-edge graph below. Illegal
// edges throw in dev (Vitest runs in dev mode so the tests catch them)
// and log + no-op in prod so a frontend state-machine bug never DOS's
// the user. The backend is the source of truth for vault state, hence
// `vaultLocked` is authoritative — it accepts from any current state.
//
// Legal transitions (any → locked via vaultLocked is always allowed):
//
//   locked      → unlocking    beginUnlock()
//   unlocking   → unlocked     unlockSucceeded(manifest, settings)
//   unlocking   → locked       unlockFailed(err)
//   unlocked    → locking      beginLock()
//   *           → locked       vaultLocked('idle' | 'manual', at)
//
// `unlocking` and `locking` carry `startedAt: number` so the UI can
// detect stuck transitions and surface a toast (consumer lands in
// Tasks 8–10).

import { writable, derived, type Readable } from 'svelte/store';
import type { AppError } from './errors';
import type { ManifestDto, SettingsDto } from './ipc';

export type SessionState =
  | { status: 'locked'; lastError: AppError | null }
  | { status: 'unlocking'; startedAt: number }
  | { status: 'unlocked'; manifest: ManifestDto; settings: SettingsDto }
  | { status: 'locking'; startedAt: number };

// Factory rather than a shared constant: each call yields a fresh
// object so the initial-write and `_resetSessionStateForTest` can never
// hand out aliased references that a test might accidentally mutate.
function initialState(): SessionState {
  return { status: 'locked', lastError: null };
}

// Internal writable — mutations gate through the transition helpers
// below. Not exported; the public `sessionState` is a read-only view.
const _internal = writable<SessionState>(initialState());

// Public subscription surface. Components consume via the `$` Svelte
// auto-subscription idiom (`$sessionState.status === 'unlocked'`).
// No `.set` / `.update` exposed — callers must use a transition helper.
export const sessionState: Readable<SessionState> = {
  subscribe: _internal.subscribe
};

// Short-lived notice surfaced when the backend `vault-locked` event
// fires (`idle` for auto-lock, `manual` for explicit-lock), or when
// the activity-tracker keep-alive IPC starts failing repeatedly. The
// discriminated union lets the toast component pick its copy and
// severity. `at` is the millisecond timestamp at which the notice
// was raised, used for de-duplication and auto-dismiss timing.
//
// `vaultLocked()` sets the `idle` / `manual` reasons automatically as
// part of the transition; `keep_alive_failing` is set directly by
// `auto_lock.ts` since it's not tied to a session-state transition.
export type AutoLockNotice =
  | { reason: 'idle'; at: number }
  | { reason: 'manual'; at: number }
  | { reason: 'keep_alive_failing'; at: number };

export const autoLockNotice = writable<AutoLockNotice | null>(null);

// Convenience selector — null whenever the session is not unlocked.
export const currentSettings = derived(sessionState, ($s) =>
  $s.status === 'unlocked' ? $s.settings : null
);

// --- Transition helpers ----------------------------------------------------

/**
 * `locked → unlocking`. Records `startedAt` so the UI can detect stuck
 * unlocks. Pass an explicit `now` for deterministic tests.
 */
export function beginUnlock(now: number = Date.now()): void {
  transition(['locked'], { status: 'unlocking', startedAt: now });
}

/**
 * `unlocking → unlocked`. Carries the manifest + settings into the
 * variant payload.
 */
export function unlockSucceeded(manifest: ManifestDto, settings: SettingsDto): void {
  transition(['unlocking'], { status: 'unlocked', manifest, settings });
}

/**
 * `unlocking → locked`. Carries the typed error so the Unlock form can
 * render `userMessageFor(err)` inline.
 */
export function unlockFailed(err: AppError): void {
  transition(['unlocking'], { status: 'locked', lastError: err });
}

/**
 * `unlocked → locking`. Records `startedAt`; the actual lock IPC fires
 * after this and the transition to `locked` happens via `vaultLocked`
 * when the backend's `vault-locked` event arrives (spec §7 — backend
 * reality is source of truth).
 */
export function beginLock(now: number = Date.now()): void {
  transition(['unlocked'], { status: 'locking', startedAt: now });
}

/**
 * `* → locked`. Authoritative end-state from the backend `vault-locked`
 * event; accepted from any current state. Also raises the matching
 * `autoLockNotice` so the toast surface can render the reason copy.
 */
export function vaultLocked(reason: 'idle' | 'manual', at: number = Date.now()): void {
  _internal.set({ status: 'locked', lastError: null });
  autoLockNotice.set({ reason, at });
}

/**
 * Test-only escape hatch — restores both stores to initial state.
 * Underscore prefix matches the `_resetActivityTrackingForTest`
 * convention in `auto_lock.ts`.
 */
export function _resetSessionStateForTest(): void {
  _internal.set(initialState());
  autoLockNotice.set(null);
}

// --- Internal --------------------------------------------------------------

/**
 * Atomic check-and-set: if `current.status` is not in `allowed`, the
 * transition is illegal and we either throw (dev) or log + no-op (prod).
 * Using `update()` rather than `get(_internal)` + `set(...)` keeps the
 * check and the set under the same store lock.
 */
function transition(
  allowed: ReadonlyArray<SessionState['status']>,
  toState: SessionState
): void {
  _internal.update((current) => {
    if (!allowed.includes(current.status)) {
      illegalTransition(current.status, toState.status, allowed);
      return current;
    }
    return toState;
  });
}

function illegalTransition(
  from: SessionState['status'],
  to: SessionState['status'],
  allowed: ReadonlyArray<SessionState['status']>
): void {
  const msg = `illegal session transition: ${from} → ${to} (allowed from: ${allowed.join(', ')})`;
  // Vite/Vitest sets `import.meta.env.DEV === true` for dev + test
  // builds; production bundles get `false`. Throwing in dev surfaces
  // state-machine bugs immediately in tests; logging in prod keeps the
  // user from seeing a hard crash for a recoverable frontend slip —
  // the backend remains the source of truth either way.
  if (import.meta.env.DEV) {
    throw new Error(msg);
  } else {
    console.error(msg);
  }
}
