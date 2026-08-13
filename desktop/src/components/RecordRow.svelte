<script lang="ts">
  import type { RecordDto } from '../lib/ipc';
  import { formatShortDate } from '../lib/format';
  import { isContentlessTombstone } from '../lib/records';

  // onDelete / onRestore / onMove are optional so existing call sites that
  // only browse (no write actions wired) keep working unchanged. When supplied,
  // a live row gets Delete + Move actions and a tombstoned row gets Restore.
  type Props = {
    record: RecordDto;
    onClick: (record: RecordDto) => void;
    onDelete?: (record: RecordDto) => void;
    onRestore?: (record: RecordDto) => void;
    onMove?: (record: RecordDto) => void;
    /** #526 — this row is the one open in the detail pane. */
    selected?: boolean;
    /** #526 — an editor is open in the detail pane. Rows go non-interactive
        so a stray click cannot silently discard an unsaved edit. */
    frozen?: boolean;
  };
  let {
    record,
    onClick,
    onDelete,
    onRestore,
    onMove,
    selected = false,
    frozen = false
  }: Props = $props();

  let countLabel = $derived(`${record.fieldCount} field${record.fieldCount === 1 ? '' : 's'}`);
  let deleted = $derived(record.tombstoned === true);
  let contentless = $derived(isContentlessTombstone(record));
  // Title first: it is what distinguishes one row from another, so it must
  // lead the accessible name too.
  let ariaLabel = $derived(
    `${record.title}, ${record.recordType} record, ${countLabel}${
      contentless ? ', no recoverable contents' : ''
    }`
  );
</script>

<div
  class="record-row-wrap"
  class:record-row--deleted={deleted}
  class:record-row--selected={selected}
  class:record-row--frozen={frozen}
>
  <button
    type="button"
    class="record-row"
    aria-label={ariaLabel}
    aria-current={selected ? 'true' : undefined}
    disabled={deleted || frozen}
    onclick={() => {
      if (!frozen) onClick(record);
    }}
  >
    <span class="record-row__title">{record.title}</span>
    {#if record.subtitle}
      <span class="record-row__subtitle">{record.subtitle}</span>
    {/if}
    {#each record.tags as tag (tag)}
      <span class="record-row__tag">{tag}</span>
    {/each}
    <span class="record-row__meta">{countLabel} · modified {formatShortDate(record.lastModMs)}</span>
    {#if contentless}
      <span class="record-row__no-content">· no recoverable contents</span>
    {/if}
  </button>

  {#if !frozen}
    {#if deleted && onRestore}
      <button type="button" class="record-row__restore" aria-label="Restore record" onclick={() => onRestore(record)}>Restore</button>
    {:else if !deleted}
      {#if onMove}
        <button type="button" class="record-row__move" aria-label="Move record" onclick={() => onMove(record)}>Move</button>
      {/if}
      {#if onDelete}
        <button type="button" class="record-row__delete" aria-label="Delete record" onclick={() => onDelete(record)}>Delete</button>
      {/if}
    {/if}
  {/if}
</div>

<style>
  .record-row__title {
    display: block;
    font-size: var(--font-size-md);
    color: var(--color-text);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .record-row__subtitle {
    display: block;
    font-size: var(--font-size-sm);
    color: var(--color-text-muted);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .record-row--selected {
    background: var(--color-primary);
    border-radius: var(--radius-sm);
  }

  .record-row--selected .record-row__title,
  .record-row--selected .record-row__subtitle {
    color: var(--color-on-primary);
  }

  /* Frozen: an editor is open. Dimmed and non-interactive, so the only way
     out of the editor stays Save or Cancel. */
  .record-row--frozen {
    opacity: 0.45;
    pointer-events: none;
  }
</style>
