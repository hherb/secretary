<script lang="ts">
  // D.1.8 "Shared with" banner — mounted at the top of the records view.
  // Loads block_recipients for the current block, shows a collapsed one-line
  // summary, and expands to a per-recipient list. Self-contained load/loadSeq
  // guard keyed by block.blockUuidHex (mirrors RecordList's own pattern).
  import {
    listBlockRecipients,
    revokeBlockFrom,
    isAppError,
    type BlockSummaryDto,
    type RecipientDto
  } from '../lib/ipc';
  import { sortRecipients, recipientLabel, summarizeRecipients } from '../lib/recipients';
  import { revokeConfirmCopy } from '../lib/revoke';
  import { userMessageFor, type AppError } from '../lib/errors';
  import ConfirmDialog from './delete/ConfirmDialog.svelte';

  type Props = { block: BlockSummaryDto };
  let { block }: Props = $props();

  let recipients = $state<RecipientDto[] | null>(null);
  let error = $state<AppError | null>(null);
  let expanded = $state(false);

  let loadSeq = 0;
  async function load() {
    const seq = ++loadSeq;
    const blockUuidHex = block.blockUuidHex;
    recipients = null;
    error = null;
    expanded = false;
    try {
      const rows = await listBlockRecipients(blockUuidHex);
      if (seq === loadSeq) recipients = sortRecipients(rows);
    } catch (e) {
      if (seq === loadSeq) error = isAppError(e) ? e : { code: 'internal' };
    }
  }

  $effect(() => {
    void block.blockUuidHex;
    void load();
  });

  // Collapsed summary: name up to a few resolved recipients, fold the rest of
  // the named ones into "+N more" and unknowns into "+N unknown".
  const summary = $derived(recipients ? summarizeRecipients(recipients) : '');

  let pendingRevoke = $state<RecipientDto | null>(null);

  async function confirmRevoke() {
    const target = pendingRevoke;
    pendingRevoke = null;
    if (!target) return;
    error = null;
    try {
      await revokeBlockFrom(block.blockUuidHex, target.uuidHex);
      await load(); // re-fetch this banner's recipient list from disk
      // load() collapses the banner; re-expand so the list stays open for a
      // follow-up revoke — matches ContactRow, which keeps its list expanded.
      // Only on a clean reload: if load() set an error, leave the banner
      // collapsed so the re-expand can't fight the error branch.
      if (!error) expanded = true;
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }
</script>

<div class="block-recipients">
  {#if error}
    {@const msg = userMessageFor(error)}
    <p class="block-recipients__error" role="alert">
      {msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}
    </p>
  {:else if recipients === null}
    <p class="block-recipients__loading">Loading recipients…</p>
  {:else}
    <button
      type="button"
      class="block-recipients__toggle"
      aria-expanded={expanded}
      onclick={() => (expanded = !expanded)}
    >
      Shared with: {summary} {expanded ? '▴' : '▾'}
    </button>
    {#if expanded}
      <ul class="block-recipients__list">
        {#each recipients as r (r.uuidHex)}
          <li class="block-recipients__row" class:block-recipients__row--unknown={r.kind === 'unknown'}>
            <span class="block-recipients__label">{recipientLabel(r)}</span>
            {#if r.kind !== 'owner'}
              <button
                type="button"
                class="block-recipients__revoke"
                aria-label={`Revoke ${recipientLabel(r)}’s access to “${block.blockName}”`}
                onclick={() => (pendingRevoke = r)}
              >
                ✕
              </button>
            {/if}
          </li>
        {/each}
      </ul>
    {/if}
  {/if}

  {#if pendingRevoke}
    {@const copy = revokeConfirmCopy(block.blockName, recipientLabel(pendingRevoke))}
    <ConfirmDialog
      title={copy.title}
      body={copy.body}
      confirmLabel={copy.confirmLabel}
      onConfirm={confirmRevoke}
      onCancel={() => (pendingRevoke = null)}
    />
  {/if}
</div>
