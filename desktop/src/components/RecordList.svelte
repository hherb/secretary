<script lang="ts">
  import { readBlock, isAppError, type BlockSummaryDto, type RecordDto } from '../lib/ipc';
  import { openRecord, back } from '../lib/browse';
  import { userMessageFor, type AppError } from '../lib/errors';
  import RecordRow from './RecordRow.svelte';

  type Props = { block: BlockSummaryDto };
  let { block }: Props = $props();

  let records = $state<RecordDto[] | null>(null);
  let error = $state<AppError | null>(null);

  $effect(() => {
    // reset before each fetch so a block change can't flash stale records
    records = null;
    error = null;
    let cancelled = false;
    readBlock(block.blockUuidHex)
      .then((dto) => { if (!cancelled) records = dto.records; })
      .catch((e) => { if (!cancelled) error = isAppError(e) ? e : { code: 'internal' }; });
    return () => { cancelled = true; };
  });
</script>

<section class="record-list">
  <button type="button" class="record-list__back" onclick={() => back()}>← {block.blockName}</button>

  {#if error}
    {@const msg = userMessageFor(error)}
    <p class="record-list__error" role="alert">{msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}</p>
  {:else if records === null}
    <p class="record-list__loading">Loading…</p>
  {:else if records.length === 0}
    <p class="record-list__empty">No records.</p>
  {:else}
    {#each records as record (record.recordUuidHex)}
      <RecordRow {record} onClick={openRecord} />
    {/each}
  {/if}
</section>
