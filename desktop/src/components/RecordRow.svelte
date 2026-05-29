<script lang="ts">
  import type { RecordDto } from '../lib/ipc';
  import { formatShortDate } from '../lib/format';

  type Props = { record: RecordDto; onClick: (record: RecordDto) => void };
  let { record, onClick }: Props = $props();

  let countLabel = $derived(`${record.fieldCount} field${record.fieldCount === 1 ? '' : 's'}`);
</script>

<button
  type="button"
  class="record-row"
  aria-label={`${record.recordType} record, ${countLabel}`}
  onclick={() => onClick(record)}
>
  <span class="record-row__type">{record.recordType}</span>
  {#each record.tags as tag (tag)}
    <span class="record-row__tag">{tag}</span>
  {/each}
  <span class="record-row__meta">{countLabel} · modified {formatShortDate(record.lastModMs)}</span>
</button>
