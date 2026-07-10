<script lang="ts">
  // Trash view (spec D.1.5) — lists trashed blocks newest-first and lets
  // the user restore one. Reached from the Vault "Trash" entry; back()
  // pops to the blocks level. Mirrors RecordList's load/error/empty shape:
  // a load() async fn, a $effect that calls it on mount, and a typed
  // AppError surfaced via userMessageFor.

  import { listTrashedBlocks, restoreBlock, purgeBlock, isAppError, type TrashedBlockDto } from '../../lib/ipc';
  import { sortTrashed } from '../../lib/trash';
  import { back } from '../../lib/browse';
  import { refreshManifest } from '../../lib/stores';
  import { userMessageFor, type AppError } from '../../lib/errors';
  import TrashedBlockRow from './TrashedBlockRow.svelte';
  import ConfirmDialog from './ConfirmDialog.svelte';
  import RetentionDialog from './RetentionDialog.svelte';
  import { authorizeWrite, ReauthCancelled } from '../../lib/writeGuard';

  let entries = $state<TrashedBlockDto[] | null>(null);
  let error = $state<AppError | null>(null);
  let showRetention = $state(false);
  let pendingPurge = $state<TrashedBlockDto | null>(null);

  // Generation guard (see RecordList): the mount load and a post-restore
  // reload can overlap, so only the newest load() writes `entries`.
  let loadSeq = 0;

  async function load() {
    const seq = ++loadSeq;
    error = null;
    try {
      const sorted = sortTrashed(await listTrashedBlocks());
      if (seq === loadSeq) entries = sorted;
    } catch (e) {
      if (seq === loadSeq) error = isAppError(e) ? e : { code: 'internal' };
    }
  }

  $effect(() => {
    void load();
  });

  async function restore(entry: TrashedBlockDto) {
    error = null;
    try {
      await authorizeWrite('Confirm restoring this block');
    } catch (err) {
      if (err === ReauthCancelled) return;
      error = isAppError(err) ? err : { code: 'internal' };
      return;
    }
    try {
      await restoreBlock(entry.blockUuidHex);
      await refreshManifest();
      await load();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }

  // Mirrors `restore`: authorize, then run the irreversible purge, then
  // refresh the manifest and reload the trash list.
  async function confirmPurge() {
    const target = pendingPurge;
    pendingPurge = null;
    if (!target) return;
    error = null;
    try {
      await authorizeWrite('Confirm permanently deleting this block');
    } catch (err) {
      if (err === ReauthCancelled) return;
      error = isAppError(err) ? err : { code: 'internal' };
      return;
    }
    try {
      await purgeBlock(target.blockUuidHex);
      await refreshManifest();
      await load();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }
</script>

<section class="trash-view">
  <button type="button" class="trash-view__back" onclick={() => back()}>← Trash</button>
  <button type="button" class="trash-view__retention" onclick={() => (showRetention = true)}>
    Run retention now
  </button>

  {#if error}
    {@const msg = userMessageFor(error)}
    <p class="trash-view__error" role="alert">{msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}</p>
  {:else if entries === null}
    <p class="trash-view__loading">Loading…</p>
  {:else if entries.length === 0}
    <p class="trash-view__empty">Trash is empty.</p>
  {:else}
    {#each entries as entry (entry.blockUuidHex)}
      <TrashedBlockRow {entry} onRestore={restore} onPurge={(e) => (pendingPurge = e)} />
    {/each}
  {/if}
</section>

{#if showRetention}
  <RetentionDialog
    onClose={() => {
      showRetention = false;
      void load();
    }}
  />
{/if}

{#if pendingPurge}
  <ConfirmDialog
    title="Delete forever?"
    body={`"${pendingPurge.blockName}" will be permanently deleted. This cannot be undone.`}
    confirmLabel="Delete forever"
    onConfirm={confirmPurge}
    onCancel={() => (pendingPurge = null)}
  />
{/if}
