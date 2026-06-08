<script lang="ts">
  import type { RecordDto } from '../lib/ipc';
  import { formatShortDate } from '../lib/format';
  import { isContentlessTombstone } from '../lib/records';

  // onDelete / onRestore are optional so existing call sites that only
  // browse (no write actions wired) keep working unchanged. When supplied,
  // a live row gets a Delete action and a tombstoned row gets Restore.
  type Props = {
    record: RecordDto;
    onClick: (record: RecordDto) => void;
    onDelete?: (record: RecordDto) => void;
    onRestore?: (record: RecordDto) => void;
  };
  let { record, onClick, onDelete, onRestore }: Props = $props();

  let countLabel = $derived(`${record.fieldCount} field${record.fieldCount === 1 ? '' : 's'}`);
  let deleted = $derived(record.tombstoned === true);
  let contentless = $derived(isContentlessTombstone(record));
  let ariaLabel = $derived(
    contentless
      ? `${record.recordType} record, ${countLabel}, no recoverable contents`
      : `${record.recordType} record, ${countLabel}`
  );
</script>

<div class="record-row-wrap" class:record-row--deleted={deleted}>
  <button
    type="button"
    class="record-row"
    aria-label={ariaLabel}
    disabled={deleted}
    onclick={() => onClick(record)}
  >
    <span class="record-row__type">{record.recordType}</span>
    {#each record.tags as tag (tag)}
      <span class="record-row__tag">{tag}</span>
    {/each}
    <span class="record-row__meta">{countLabel} · modified {formatShortDate(record.lastModMs)}</span>
    {#if contentless}
      <span class="record-row__no-content">· no recoverable contents</span>
    {/if}
  </button>

  {#if deleted && onRestore}
    <button
      type="button"
      class="record-row__restore"
      aria-label="Restore record"
      onclick={() => onRestore(record)}
    >
      Restore
    </button>
  {:else if !deleted && onDelete}
    <button
      type="button"
      class="record-row__delete"
      aria-label="Delete record"
      onclick={() => onDelete(record)}
    >
      Delete
    </button>
  {/if}
</div>
