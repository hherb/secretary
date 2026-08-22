<script lang="ts">
  import { openEditRecord } from '../lib/browse';
  import type { BlockSummaryDto, RecordDto } from '../lib/ipc';
  import FieldRow from './FieldRow.svelte';

  type Props = { block: BlockSummaryDto; record: RecordDto };
  let { block, record }: Props = $props();
</script>

<section class="field-viewer">
  <h2 class="field-viewer__title">{record.title}</h2>
  <button type="button" class="field-viewer__edit" onclick={() => openEditRecord(block, record)}>Edit</button>
  {#each record.tags as tag (tag)}<span class="field-viewer__tag">{tag}</span>{/each}

  {#if record.fields.length === 0}
    <p class="field-viewer__empty">No fields.</p>
  {:else}
    {#each record.fields as field (field.name)}
      <FieldRow blockUuidHex={block.blockUuidHex} recordUuidHex={record.recordUuidHex} {field} />
    {/each}
  {/if}
</section>
