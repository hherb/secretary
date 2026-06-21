// Pure write-reauth policy. The ENTIRE grace-window decision lives here so it
// is host-testable (vitest) with zero I/O — mirrors the iOS `needsReauth`
// pure function (#275). The stateful gate (lastAuthAt, the prompt, the verify
// IPC) lives in writeGuard.ts; this module decides only "prompt or not".

export interface NeedsReauthOpts {
  /** The `require_password_before_edits` setting. */
  enabled: boolean;
  /** Wall-clock ms of the last successful auth this session, or null if none. */
  lastAuthAtMs: number | null;
  /** Current wall-clock ms. */
  nowMs: number;
  /** The configured grace window in ms. */
  windowMs: number;
}

/**
 * True when a mutating write must prompt for the password first.
 *
 * - disabled            → false (gate off)
 * - never authed (null) → true
 * - elapsed >= window   → true  (boundary inclusive)
 * - else                → false (inside grace)
 *
 * `nowMs`/`lastAuthAtMs` are wall-clock (`Date.now()` at the call site).
 * Clock-jump behaviour: a FORWARD jump grows `nowMs - lastAuthAtMs`, so it only
 * ever re-prompts early (fail-safe). A BACKWARD jump shrinks it, widening the
 * grace window so a prompt may be deferred — but the effect is bounded by the
 * jump size, lives only within one unlocked session (lock reseeds the clock),
 * and never bypasses the gate for a session that has not authed at all (null →
 * always prompts). This matches the iOS gate (#275); a monotonic clock isn't
 * worth the friction for a presence-assurance window.
 */
export function needsReauth(opts: NeedsReauthOpts): boolean {
  if (!opts.enabled) return false;
  if (opts.lastAuthAtMs === null) return true;
  return opts.nowMs - opts.lastAuthAtMs >= opts.windowMs;
}
