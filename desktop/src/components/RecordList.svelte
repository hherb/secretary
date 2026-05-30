<script lang="ts">
  import {
    readBlock,
    tombstoneRecord,
    resurrectRecord,
    isAppError,
    type BlockSummaryDto,
    type RecordDto
  } from '../lib/ipc';
  import { openRecord, openNewRecord, back } from '../lib/browse';
  import { userMessageFor, type AppError } from '../lib/errors';
  import RecordRow from './RecordRow.svelte';
  import ConfirmDialog from './delete/ConfirmDialog.svelte';

  type Props = { block: BlockSummaryDto };
  let { block }: Props = $props();

  let records = $state<RecordDto[] | null>(null);
  let error = $state<AppError | null>(null);
  let showDeleted = $state(false);
  // Record awaiting delete confirmation; the ConfirmDialog mounts while set.
  let pendingDelete = $state<RecordDto | null>(null);

  async function load() {
    // reset before each fetch so a block change can't flash stale records
    records = null;
    error = null;
    try {
      const dto = await readBlock(block.blockUuidHex, showDeleted);
      records = dto.records;
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }

  $effect(() => {
    // Explicitly read both reactive deps in the effect body so toggling
    // "Show deleted" OR switching blocks re-runs the load — load() reads
    // them again internally, but reading them here is what registers the
    // dependency for the effect (and avoids any state_referenced_locally
    // ambiguity from the analyzer).
    void block.blockUuidHex;
    void showDeleted;
    void load();
  });

  async function onDelete(record: RecordDto) {
    pendingDelete = record;
  }

  async function confirmDelete() {
    const target = pendingDelete;
    if (!target) return;
    pendingDelete = null;
    error = null;
    try {
      await tombstoneRecord(block.blockUuidHex, target.recordUuidHex);
      await load();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }

  async function onRestore(record: RecordDto) {
    error = null;
    try {
      await resurrectRecord(block.blockUuidHex, record.recordUuidHex);
      await load();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }
</script>

<section class="record-list">
  <button type="button" class="record-list__back" onclick={() => back()}>← {block.blockName}</button>
  <button type="button" class="record-list__add" onclick={() => openNewRecord(block)}>+ Add record</button>

  <label class="record-list__show-deleted">
    <input type="checkbox" bind:checked={showDeleted} />
    Show deleted
  </label>

  {#if error}
    {@const msg = userMessageFor(error)}
    <p class="record-list__error" role="alert">{msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}</p>
  {:else if records === null}
    <p class="record-list__loading">Loading…</p>
  {:else if records.length === 0}
    <p class="record-list__empty">No records.</p>
  {:else}
    {#each records as record (record.recordUuidHex)}
      <RecordRow {record} onClick={openRecord} {onDelete} {onRestore} />
    {/each}
  {/if}
</section>

{#if pendingDelete}
  <ConfirmDialog
    title="Delete this record?"
    body="It moves to deleted and can be restored via “Show deleted”."
    confirmLabel="Delete"
    onConfirm={confirmDelete}
    onCancel={() => (pendingDelete = null)}
  />
{/if}
