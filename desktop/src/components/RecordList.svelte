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
  import BlockRecipients from './BlockRecipients.svelte';
  import ConfirmDialog from './delete/ConfirmDialog.svelte';
  import { isContentlessTombstone } from '../lib/records';

  type Props = { block: BlockSummaryDto };
  let { block }: Props = $props();

  let records = $state<RecordDto[] | null>(null);
  let error = $state<AppError | null>(null);
  let showDeleted = $state(false);
  // Record awaiting delete confirmation; the ConfirmDialog mounts while set.
  let pendingDelete = $state<RecordDto | null>(null);
  // Record awaiting resurrect confirmation (only set for a contentless
  // tombstone — a resurrect that would bring back an empty shell).
  let pendingRestore = $state<RecordDto | null>(null);

  // Monotonic generation counter guarding against out-of-order fetches: each
  // load() bumps it and only writes state if it is still the newest call. One
  // guard covers BOTH triggers — the $effect (block switch / "Show deleted"
  // toggle) and the imperative reloads after a delete/resurrect — so a
  // superseded in-flight readBlock can never clobber a newer result.
  let loadSeq = 0;

  async function load() {
    const seq = ++loadSeq;
    // Snapshot the reactive deps up front; reset before each fetch so a block
    // change can't flash stale records.
    const blockUuidHex = block.blockUuidHex;
    const includeDeleted = showDeleted;
    records = null;
    error = null;
    try {
      const dto = await readBlock(blockUuidHex, includeDeleted);
      if (seq === loadSeq) records = dto.records;
    } catch (e) {
      if (seq === loadSeq) error = isAppError(e) ? e : { code: 'internal' };
    }
  }

  $effect(() => {
    // Register both reactive deps so toggling "Show deleted" OR switching
    // blocks re-runs the fetch. load() reads them again (synchronously, before
    // its first await), but these `void` reads are what subscribe the effect.
    // We deliberately do NOT read `records`/`error` here — writing them is
    // fine, but reading would make the effect self-trigger into a loop.
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

  function onRestore(record: RecordDto) {
    // A contentless tombstone resurrects to an empty shell — confirm first so
    // the empty result is expected, not a surprise. A still-filled tombstone
    // resurrects one-click (lossless undelete, unchanged behaviour).
    if (isContentlessTombstone(record)) {
      pendingRestore = record;
      return;
    }
    void doRestore(record);
  }

  async function doRestore(record: RecordDto) {
    error = null;
    try {
      await resurrectRecord(block.blockUuidHex, record.recordUuidHex);
      await load();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }

  async function confirmRestore() {
    const target = pendingRestore;
    if (!target) return;
    pendingRestore = null;
    await doRestore(target);
  }
</script>

<section class="record-list">
  <button type="button" class="record-list__back" onclick={() => back()}>← {block.blockName}</button>
  <BlockRecipients {block} />
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
    title=”Delete this record?”
    body=”It moves to deleted and can be restored via “Show deleted”.”
    confirmLabel=”Delete”
    onConfirm={confirmDelete}
    onCancel={() => (pendingDelete = null)}
  />
{/if}

{#if pendingRestore}
  <ConfirmDialog
    title=”Resurrect an empty record?”
    body=”This record has no stored contents to recover — resurrecting brings it back with only its type and tags. Contents are discarded when a record&apos;s deletion is merged from another device.”
    confirmLabel=”Resurrect”
    onConfirm={confirmRestore}
    onCancel={() => (pendingRestore = null)}
  />
{/if}
