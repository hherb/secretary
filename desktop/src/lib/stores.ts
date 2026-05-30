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
import { isAppError, getManifest, type ManifestDto, type SettingsDto } from './ipc';

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
// fires with `reason='auto'` (an idle-timeout lock), or when the
// activity-tracker keep-alive IPC starts failing repeatedly. The
// discriminated union lets the toast component pick its copy. `at`
// is the millisecond timestamp at which the notice was raised, used
// to reset the toast's auto-dismiss timer on a fresh notice.
//
// `vaultLocked('idle', ...)` raises the notice as part of the
// transition. `vaultLocked('manual', ...)` intentionally does NOT —
// the user just clicked Lock themselves, no surface is needed to
// inform them — and an entry-level `'manual'` reason in this union
// would invite a dead render path at the toast surface. The filter
// lives in the producer; downstream consumers see only the reasons
// that actually warrant a notice.
//
// `keep_alive_failing` is set directly by `auto_lock.ts` since it's
// not tied to a session-state transition.
export type AutoLockNotice =
  | { reason: 'idle'; at: number }
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
 * variant payload, and clears any pending `autoLockNotice` so a stale
 * notice from a prior lock cycle does not survive into the new
 * unlocked session (a user who returned to an undismissed auto-lock
 * toast and unlocked would otherwise see it linger on top of the
 * Vault until the dismiss timer eventually fires; spec §12 ties the
 * notice to the lock event, not to the cross-session interval).
 */
export function unlockSucceeded(manifest: ManifestDto, settings: SettingsDto): void {
  autoLockNotice.set(null);
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
 * event; accepted from any current state. Raises `autoLockNotice` ONLY
 * for the `'idle'` reason — explicit user-lock (`'manual'`) does not
 * need a confirmation surface (the user just clicked Lock themselves).
 * Centralising this filter in the producer keeps the AutoLockNotice
 * union narrow (no `'manual'` variant) and removes dead arms from the
 * toast surface — see the AutoLockNotice doc-comment above for the
 * full altitude argument.
 */
export function vaultLocked(reason: 'idle' | 'manual', at: number = Date.now()): void {
  _internal.set({ status: 'locked', lastError: null });
  if (reason === 'idle') {
    autoLockNotice.set({ reason, at });
  }
}

/**
 * `unlocked → unlocked`. In-place settings replacement after a successful
 * `set_settings` IPC. The manifest reference is preserved (same object
 * identity). Downstream `$derived` selectors keyed on manifest fields
 * will re-evaluate when this update fires (Svelte 5 tracks the outer
 * state), but they produce identical values so consumers see no change.
 * Only `currentSettings` consumers (or anything reading the variant's
 * `settings` field directly) propagate.
 *
 * Legal from `unlocked` only; SettingsDialog can only be opened from the
 * Vault route, which only mounts in the `unlocked` state, so a non-
 * `unlocked` caller is a state-machine bug. Callers that may race with
 * an inbound `vault-locked` event (e.g. SettingsDialog after an awaited
 * IPC) should peek `$sessionState.status` and skip this helper if no
 * longer `unlocked` — the backend has already persisted the change and
 * the next unlock will observe it.
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
 * `unlocked → unlocked` (manifest refresh). Fetches a fresh manifest from
 * the backend and replaces the one in the current unlocked session. Legal
 * only while status === 'unlocked'; callers that may race with a
 * `vault-locked` event should guard on the post-await status (if the vault
 * locked during the IPC flight, `_internal` is already `locked` and this
 * update is a no-op — the user will need to unlock again anyway).
 *
 * Called after `createBlock` / `saveRecord` / `saveRecordEdit` so the
 * browse panes (blocks list, RecordList) reflect the write without a
 * full re-unlock cycle.
 */
export async function refreshManifest(): Promise<void> {
  const manifest = await getManifest();
  _internal.update((current) => {
    if (current.status !== 'unlocked') return current;
    return { status: 'unlocked', manifest, settings: current.settings };
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
