<script lang="ts">
  // Combined sync indicator + trigger in the TopBar (D.1.14). The pill shows
  // the last-synced label and IS the "Sync now" control. Clicking it runs the
  // write re-auth gate, then syncs through the open session (no password per
  // pass, #732); the backend refreshes the session on every arm that wrote or
  // accepted a manifest. Self-contained: reads sync_status on mount and after
  // each sync; on a data-changing outcome it calls the global refreshManifest
  // so the records view re-reads the refreshed session.
  import { onMount } from 'svelte';
  import { syncNow, syncStatus, isAppError } from '../lib/ipc';
  import { refreshManifest } from '../lib/stores';
  import { authorizeWrite, ReauthCancelled } from '../lib/writeGuard';
  import { userMessageFor } from '../lib/errors';
  import {
    lastSyncedLabel,
    syncOutcomeMessage,
    syncChangedData,
    type SyncStatusDto,
    type SyncOutcome,
    type SyncMessage
  } from '../lib/sync';
  import ConflictResolutionDialog from './ConflictResolutionDialog.svelte';
  import Sync from './icons/Sync.svelte';

  // Single-call-site constant — keep local rather than promoting to
  // lib/constants.ts (per feedback_pure_functions's "second call site"
  // trigger; lib/constants.ts mirrors Rust-side bounds, not notice UX).
  const SYNC_NOTICE_DISMISS_MS = 5_000;

  let status = $state<SyncStatusDto | null>(null);
  let busy = $state(false);
  let notice = $state<SyncMessage | null>(null);
  // The pending conflict detail, handed to the resolution dialog.
  let conflicts = $state<Extract<SyncOutcome, { kind: 'conflictsPending' }> | null>(null);

  const label = $derived(status ? lastSyncedLabel(status, Date.now()) : 'Sync…');
  // Only fold the status into the accessible name once it has loaded — before
  // then `label` is the "Sync…" placeholder, which would announce as a
  // meaningless "Sync now — sync…".
  const ariaLabel = $derived(status ? `Sync now — ${label.toLowerCase()}` : 'Sync now');

  async function loadStatus() {
    try {
      status = await syncStatus();
    } catch {
      // Status is informational; a read failure leaves the prior label.
    }
  }

  onMount(loadStatus);

  function errorNotice(err: unknown): SyncMessage {
    const msg = userMessageFor(isAppError(err) ? err : { code: 'internal' });
    return { kind: 'error', text: msg.actionHint ? `${msg.title} — ${msg.actionHint}` : msg.title };
  }

  async function syncClicked() {
    if (busy) return;
    notice = null;
    try {
      await authorizeWrite('Confirm syncing this vault');
    } catch (err) {
      if (err !== ReauthCancelled) notice = errorNotice(err);
      return;
    }
    busy = true;
    try {
      const outcome = await syncNow();
      if (outcome.kind === 'conflictsPending') {
        conflicts = outcome;
      } else {
        await onSynced(outcome);
      }
    } catch (err) {
      notice = errorNotice(err);
    } finally {
      busy = false;
    }
  }

  async function onSynced(outcome: SyncOutcome) {
    notice = syncOutcomeMessage(outcome);
    await loadStatus();
    if (syncChangedData(outcome)) {
      await refreshManifest();
    }
  }

  async function onResolved(outcome: SyncOutcome) {
    conflicts = null;
    await onSynced(outcome); // reuse the post-sync handler (notice + status reload + manifest refresh)
  }

  function onResolveCancel() {
    conflicts = null;
  }

  // Auto-dismiss: when a notice appears, clear it after SYNC_NOTICE_DISMISS_MS.
  // Re-runs whenever `notice` changes so a new notice resets the timer;
  // returning clearTimeout ensures no late-firing set on unmount.
  $effect(() => {
    if (notice === null) return;
    const timerId = setTimeout(() => { notice = null; }, SYNC_NOTICE_DISMISS_MS);
    return () => clearTimeout(timerId);
  });
</script>

<div class="sync-pill">
  <button
    type="button"
    class="sync-pill__button"
    onclick={syncClicked}
    disabled={busy}
    aria-label={ariaLabel}
    title="Sync now"
  >
    <Sync />
    <span class="sync-pill__label">{label}</span>
  </button>

  {#if notice}
    <span
      class="sync-pill__notice sync-pill__notice--{notice.kind}"
      role={notice.kind === 'success' ? 'status' : 'alert'}
    >
      {notice.text}
    </span>
  {/if}
</div>

{#if conflicts}
  <ConflictResolutionDialog
    vetoes={conflicts.vetoes}
    collisions={conflicts.collisions}
    manifestHash={conflicts.manifestHash}
    {onResolved}
    onCancel={onResolveCancel}
  />
{/if}
