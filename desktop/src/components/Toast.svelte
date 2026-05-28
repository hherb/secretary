<script lang="ts">
  // Toast — auto-dismissing notice surface for the AutoLockNotice
  // discriminated union. Spec §12: when the vault auto-locks due to
  // inactivity the user sees a brief banner explaining why; the same
  // surface also carries the `keep_alive_failing` heads-up raised by
  // lib/auto_lock.ts when repeated notifyActivity rejections suggest
  // the IPC keep-alive is broken.
  //
  // Contract (pinned by Toast.test.ts):
  //   - Reason-specific copy: `idle` and `keep_alive_failing` get
  //     distinct messages. The `AutoLockNotice` union is narrow by
  //     construction (`'manual'` is filtered at the producer in
  //     `stores.ts::vaultLocked`), so the switch below is exhaustive
  //     over the only reasons that ever reach this component.
  //   - Auto-dismiss after TOAST_AUTO_DISMISS_MS by clearing
  //     `autoLockNotice` (which unmounts the toast via App's {#if}).
  //   - × button clears the notice immediately.
  //   - aria-live="polite" + role="status" so screen readers announce
  //     without stealing focus.
  //   - A fresh notice (changed `at`) resets the dismiss timer so the
  //     new notice gets the full window.
  //   - Cleanup on unmount: no late `autoLockNotice.set(null)` firing.

  import { autoLockNotice, type AutoLockNotice } from '../lib/stores';

  type Props = { notice: AutoLockNotice };
  let { notice }: Props = $props();

  // Single-call-site constant — keep local rather than promoting to
  // lib/constants.ts (per feedback_pure_functions's "second call site"
  // trigger; lib/constants.ts mirrors Rust-side bounds, not toast UX).
  const TOAST_AUTO_DISMISS_MS = 5_000;

  // Reason-to-copy mapping. Exhaustive over the (narrow) AutoLockNotice
  // union; if a new reason is added, the switch becomes non-exhaustive
  // and tsc surfaces the missing arm at compile time.
  function messageFor(n: AutoLockNotice): string {
    switch (n.reason) {
      case 'idle':
        return 'Vault auto-locked due to inactivity';
      case 'keep_alive_failing':
        return 'Activity tracking is failing — the vault may lock unexpectedly';
    }
  }

  function dismiss(): void {
    autoLockNotice.set(null);
  }

  // $effect re-runs whenever `notice.at` changes (Svelte 5 tracks the
  // specific signal read inside the effect). Keying on `.at` rather
  // than the prop reference is the semantic dep — the test's
  // "fresh notice resets the timer" contract is exactly about a new
  // `at` value getting a fresh dismiss window. The `void` makes the
  // read explicit and silences tsc's noUnusedLocals concern; reading
  // a Svelte 5 prop getter has the side effect of registering a dep,
  // so esbuild's pure-expression elimination cannot strip it.
  $effect(() => {
    void notice.at;
    const timerId = setTimeout(dismiss, TOAST_AUTO_DISMISS_MS);
    return () => clearTimeout(timerId);
  });
</script>

<div class="toast" role="status" aria-live="polite">
  <span class="toast__message">{messageFor(notice)}</span>
  <button
    type="button"
    class="toast__dismiss"
    aria-label="Dismiss"
    onclick={dismiss}
  >×</button>
</div>
