// Pure reveal-lifecycle timing. A revealed secret auto-re-masks after a
// delay; copying schedules a best-effort clipboard clear. The timer logic
// is isolated here (no DOM, no clipboard I/O) so components stay thin and
// the timing is unit-testable with fake timers. Uses the ambient
// setTimeout/clearTimeout (jsdom + browser both provide them); fake-timer
// tests intercept those.

export interface CancellableTimer {
  /** (Re)start the timer; resets any pending fire. */
  start(): void;
  /** Cancel a pending fire (no-op if not running). */
  cancel(): void;
}

/** A one-shot timer that fires `cb` `delayMs` after the latest `start()`.
 *  `start()` debounces (resets the pending fire); `cancel()` clears it. */
export function createAutoHideTimer(cb: () => void, delayMs: number): CancellableTimer {
  let handle: ReturnType<typeof setTimeout> | null = null;
  const cancel = (): void => {
    if (handle !== null) {
      clearTimeout(handle);
      handle = null;
    }
  };
  return {
    start(): void {
      cancel();
      handle = setTimeout(() => {
        handle = null;
        cb();
      }, delayMs);
    },
    cancel
  };
}
