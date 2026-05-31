<script lang="ts">
  // Trash view (spec D.1.5) — lists trashed blocks newest-first and lets
  // the user restore one. Reached from the Vault "Trash" entry; back()
  // pops to the blocks level. Mirrors RecordList's load/error/empty shape:
  // a load() async fn, a $effect that calls it on mount, and a typed
  // AppError surfaced via userMessageFor.

  import { listTrashedBlocks, restoreBlock, isAppError, type TrashedBlockDto } from '../../lib/ipc';
  import { sortTrashed } from '../../lib/trash';
  import { back } from '../../lib/browse';
  import { refreshManifest } from '../../lib/stores';
  import { userMessageFor, type AppError } from '../../lib/errors';
  import TrashedBlockRow from './TrashedBlockRow.svelte';

  let entries = $state<TrashedBlockDto[] | null>(null);
  let error = $state<AppError | null>(null);

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
      await restoreBlock(entry.blockUuidHex);
      await refreshManifest();
      await load();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }
</script>

<section class="trash-view">
  <button type="button" class="trash-view__back" onclick={() => back()}>← Trash</button>

  {#if error}
    {@const msg = userMessageFor(error)}
    <p class="trash-view__error" role="alert">{msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}</p>
  {:else if entries === null}
    <p class="trash-view__loading">Loading…</p>
  {:else if entries.length === 0}
    <p class="trash-view__empty">Trash is empty.</p>
  {:else}
    {#each entries as entry (entry.blockUuidHex)}
      <TrashedBlockRow {entry} onRestore={restore} />
    {/each}
  {/if}
</section>
