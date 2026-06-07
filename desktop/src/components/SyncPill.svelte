<script lang="ts">
  // Combined sync indicator + trigger in the TopBar (D.1.14). The pill shows
  // the last-synced label and IS the "Sync now" control; clicking it opens
  // SyncPasswordDialog. Self-contained: reads sync_status on mount and after
  // each sync; on a data-changing outcome it calls the global refreshManifest
  // (the in-memory manifest goes stale when sync applies peer changes).
  import { onMount } from 'svelte';
  import { syncStatus } from '../lib/ipc';
  import { refreshManifest } from '../lib/stores';
  import {
    lastSyncedLabel,
    syncOutcomeMessage,
    syncChangedData,
    type SyncStatusDto,
    type SyncOutcome,
    type SyncMessage
  } from '../lib/sync';
  import SyncPasswordDialog from './SyncPasswordDialog.svelte';
  import Sync from './icons/Sync.svelte';

  // Single-call-site constant — keep local rather than promoting to
  // lib/constants.ts (per feedback_pure_functions's "second call site"
  // trigger; lib/constants.ts mirrors Rust-side bounds, not notice UX).
  const SYNC_NOTICE_DISMISS_MS = 5_000;

  let status = $state<SyncStatusDto | null>(null);
  let dialogOpen = $state(false);
  let notice = $state<SyncMessage | null>(null);

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

  async function onSynced(outcome: SyncOutcome) {
    dialogOpen = false;
    notice = syncOutcomeMessage(outcome);
    await loadStatus();
    if (syncChangedData(outcome)) {
      await refreshManifest();
    }
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
    onclick={() => { notice = null; dialogOpen = true; }}
    aria-label={ariaLabel}
    title="Sync now"
  >
    <Sync />
    {label}
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

{#if dialogOpen}
  <SyncPasswordDialog {onSynced} onCancel={() => (dialogOpen = false)} />
{/if}
