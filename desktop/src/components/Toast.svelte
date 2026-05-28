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
  //     distinct messages. `manual` is unhandled here on purpose —
  //     App.svelte filters it out before mounting Toast, per the plan
  //     ("click Lock manually → no toast"). Defence-in-depth: if a
  //     manual notice ever slips past the filter, we still render the
  //     dismiss button so the user can clear it.
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

  // Reason-to-copy mapping. `manual` deliberately falls through to an
  // empty string — App.svelte filters this reason before mount, so this
  // value only surfaces if a regression at the parent passes a manual
  // notice in. The × button still works in that case.
  function messageFor(n: AutoLockNotice): string {
    switch (n.reason) {
      case 'idle':
        return 'Vault auto-locked due to inactivity';
      case 'keep_alive_failing':
        return 'Activity tracking is failing — the vault may lock unexpectedly';
      case 'manual':
        return '';
    }
  }

  function dismiss(): void {
    autoLockNotice.set(null);
  }

  // $effect re-runs whenever `notice` changes (Svelte 5 tracks the prop
  // reference). Each notice gets its own setTimeout; the returned
  // cleanup clears it on prop change or unmount, so a stale timer
  // never wipes a fresh notice and unmount never leaves a late firing
  // behind.
  $effect(() => {
    // Reading the prop registers it as a dep of this effect.
    void notice;
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
