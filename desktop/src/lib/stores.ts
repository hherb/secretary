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
//   unlocked    → unlocked     settingsUpdated(newSettings)
//   locking     → locked       lockFailed(err)
//   *           → locked       vaultLocked('idle' | 'manual', at)
//
// `unlocking` and `locking` carry `startedAt: number` so the UI can
// detect stuck transitions and surface a toast (consumer lands in
// Tasks 8–10).

import { writable, derived, type Readable } from 'svelte/store';
import type { AppError } from './errors';
import { isAppError, type ManifestDto, type SettingsDto } from './ipc';

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
 * `unlocking → locked`. Accepts `unknown` (caller passes a catch param)
 * and narrows defensively — the IPC layer already coerces non-AppError
 * rejections via `call()` in `ipc.ts`, but doing the narrowing here too
 * means the helper's contract holds even if a future refactor moves
 * error mapping away from the IPC boundary. Non-AppError shapes are
 * captured as `{ code: 'internal' }` so `userMessageFor` always has a
 * valid discriminant to render.
 */
export function unlockFailed(err: unknown): void {
  transition(['unlocking'], { status: 'locked', lastError: narrowAppError(err) });
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
 * `unlocked → unlocked`. In-place settings replacement after a successful
 * `set_settings` IPC. Manifest reference is preserved (same object
 * identity) so downstream `$derived` selectors keyed on it don't churn —
 * only consumers of `currentSettings` (or anything reading the variant's
 * `settings` field directly) see a change.
 *
 * Legal from `unlocked` only; SettingsDialog can only be opened from the
 * Vault route, which only mounts in the `unlocked` state, so a non-
 * `unlocked` caller is a state-machine bug.
 */
export function settingsUpdated(newSettings: SettingsDto): void {
  _internal.update((current) => {
    if (current.status !== 'unlocked') {
      illegalTransition(current.status, 'unlocked', ['unlocked']);
      return current;
    }
    return { status: 'unlocked', manifest: current.manifest, settings: newSettings };
  });
}

/**
 * `locking → locked`. Captures the typed `lock` IPC failure so the
 * locked screen can surface what went wrong. Per spec §7 the backend's
 * `lock` is documented infallible, but the Tauri transport can still
 * reject (mutex poisoning, event-emit failure) and without this helper
 * the UI would stick in `locking` forever waiting for a `vault-locked`
 * event that won't arrive. Force-transitioning to `locked` accepts a
 * small UX cost (user may see "locked" while backend is still unlocked
 * if the mutex was poisoned) in exchange for never stranding the user.
 * The auto-lock timer keeps running server-side and will eventually
 * reconcile reality.
 *
 * Accepts `unknown`; see `unlockFailed` for the narrowing rationale.
 */
export function lockFailed(err: unknown): void {
  transition(['locking'], { status: 'locked', lastError: narrowAppError(err) });
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
 * Narrow a catch-param `unknown` to a typed `AppError`. Non-AppError
 * shapes (a bare string, a panic Error, a future Rust variant not yet
 * in the union) coerce to `{ code: 'internal' }` and the original is
 * logged so the developer-facing breadcrumb survives. Same coercion
 * `ipc.ts::call` performs — keeping it here too means the helpers'
 * contracts hold independent of IPC-layer details.
 */
function narrowAppError(err: unknown): AppError {
  if (isAppError(err)) return err;
  console.error('session-state helper received non-AppError rejection', err);
  return { code: 'internal' };
}

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
