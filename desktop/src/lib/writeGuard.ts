// Stateful write re-auth gate. Holds `lastAuthAtMs`, decides via the pure
// `needsReauth`, and on a needed prompt drives the shared reauth modal.
// Mirrors the iOS GraceWindowReauthGate (#275): the policy is pure, the gate
// is stateful, and a refusal throws so the caller leaves its dialog open and
// runs no write.
//
// Design B split: the DIALOG owns `verifyPassword` (it calls the IPC directly,
// shows inline wrong-password errors, and retries until success or cancel).
// The guard's `prompt(reason)` resolves only AFTER the dialog has successfully
// verified the password. On cancel, `prompt` rejects with `ReauthCancelled`.
// This means the guard has no retry loop and no `verify` seam — it awaits a
// single `prompt` call per authorization round.

import { get } from 'svelte/store';
import { needsReauth } from './reauth';
import { sessionState, openReauthPrompt, closeReauthPrompt } from './stores';
import { REAUTH_WINDOW_DEFAULT_MS } from './constants';

/** Rejected (thrown) when the user cancels the re-auth prompt. Identity-compared. */
export const ReauthCancelled: unique symbol = Symbol('ReauthCancelled');

interface WriteGuardSeam {
  readSettings: () => { enabled: boolean; windowMs: number };
  now: () => number;
  /**
   * Open the re-auth prompt and wait for the outcome.
   * Resolves when the write is authorized (dialog verified the password).
   * Rejects with `ReauthCancelled` when the user cancels.
   */
  prompt: (reason: string) => Promise<void>;
}

// --- Production seam -------------------------------------------------------

// Pending promise callbacks for the in-flight reauth prompt (one at a time).
let pendingResolve: (() => void) | null = null;
let pendingReject: ((reason: unknown) => void) | null = null;

function productionSeam(): WriteGuardSeam {
  return {
    readSettings: () => {
      const s = get(sessionState);
      if (s.status !== 'unlocked') {
        // Locked: treat as disabled — writes will fail at the backend with
        // NotUnlocked anyway; we don't prompt on a dead session.
        return { enabled: false, windowMs: REAUTH_WINDOW_DEFAULT_MS };
      }
      return {
        enabled: s.settings.requirePasswordBeforeEdits,
        windowMs: s.settings.reauthGraceWindowMs
      };
    },
    now: () => Date.now(),
    prompt: (reason: string) =>
      new Promise<void>((resolve, reject) => {
        pendingResolve = resolve;
        pendingReject = reject;
        openReauthPrompt(reason);
      })
  };
}

// --- Module state ----------------------------------------------------------

let seam: WriteGuardSeam = productionSeam();
let lastAuthAtMs: number | null = null;

// --- Public API ------------------------------------------------------------

/** Test-only seam injection. */
export function __setWriteGuardTestSeam(s: WriteGuardSeam): void {
  seam = s;
}

/**
 * Reset guard state. Call on lock/unlock so a new session re-prompts.
 * Also restores the production seam and clears any pending promise callbacks.
 */
export function resetReauthGuard(): void {
  lastAuthAtMs = null;
  pendingResolve = null;
  pendingReject = null;
  seam = productionSeam();
}

/** Seed the grace-window clock at unlock (the unlock password proves presence). */
export function seedReauthClock(nowMs: number): void {
  lastAuthAtMs = nowMs;
}

/**
 * The write-authorization chokepoint.
 *
 * Resolves immediately when reauth is not needed (disabled or within the grace
 * window). Otherwise opens the reauth prompt and awaits the dialog outcome:
 * - Dialog calls `__resolveReauthPrompt()` after successful `verifyPassword` →
 *   advances `lastAuthAtMs` and resolves.
 * - Dialog calls `__cancelReauthPrompt()` → rejects with `ReauthCancelled`
 *   (clock is NOT advanced; the next call will prompt again).
 *
 * Callers that catch `ReauthCancelled` should abort their write; any other
 * rejection propagates an IPC/transport error from `verifyPassword` (surfaced
 * via `__resolveReauthPrompt` → but note the dialog handles wrong-password
 * inline and only resolves on success, so the error path is effectively
 * transport-only).
 */
export async function authorizeWrite(reason: string): Promise<void> {
  const { enabled, windowMs } = seam.readSettings();
  if (!needsReauth({ enabled, lastAuthAtMs, nowMs: seam.now(), windowMs })) {
    return;
  }
  // `prompt` resolves when the dialog has verified the password (design B).
  // On cancel it rejects with ReauthCancelled — we let that propagate.
  await seam.prompt(reason);
  lastAuthAtMs = seam.now();
}

// --- Dialog callbacks (production seam only) -------------------------------

/**
 * Called by the ReauthPasswordDialog after a successful `verifyPassword` IPC.
 * Closes the prompt and resolves the pending `authorizeWrite` promise.
 */
export function __resolveReauthPrompt(): void {
  closeReauthPrompt();
  const resolve = pendingResolve;
  pendingResolve = null;
  pendingReject = null;
  resolve?.();
}

/**
 * Called by the ReauthPasswordDialog when the user cancels.
 * Closes the prompt and rejects the pending `authorizeWrite` promise with
 * `ReauthCancelled`.
 */
export function __cancelReauthPrompt(): void {
  closeReauthPrompt();
  const reject = pendingReject;
  pendingResolve = null;
  pendingReject = null;
  reject?.(ReauthCancelled);
}
