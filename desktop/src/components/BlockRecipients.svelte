<script lang="ts">
  // D.1.8 "Shared with" banner — mounted at the top of the records view.
  // Loads block_recipients for the current block, shows a collapsed one-line
  // summary, and expands to a per-recipient list. Self-contained load/loadSeq
  // guard keyed by block.blockUuidHex (mirrors RecordList's own pattern).
  import { listBlockRecipients, isAppError, type BlockSummaryDto, type RecipientDto } from '../lib/ipc';
  import { sortRecipients, recipientLabel } from '../lib/recipients';
  import { userMessageFor, type AppError } from '../lib/errors';

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

  // Collapsed summary: name resolved recipients, fold unknowns into a count.
  const summary = $derived.by(() => {
    if (!recipients) return '';
    const named = recipients.filter((r) => r.kind !== 'unknown').map(recipientLabel);
    const unknownCount = recipients.filter((r) => r.kind === 'unknown').length;
    const parts = [...named];
    if (unknownCount > 0) parts.push(`+${unknownCount} unknown`);
    return parts.join(', ');
  });
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
            {recipientLabel(r)}
          </li>
        {/each}
      </ul>
    {/if}
  {/if}
</div>
