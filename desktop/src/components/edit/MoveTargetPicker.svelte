<script lang="ts">
  import { listBlocks, isAppError, type BlockSummaryDto } from '../../lib/ipc';
  import { isSameBlock } from '../../lib/blockCrud';
  import { userMessageFor, type AppError } from '../../lib/errors';

  let { sourceBlockUuidHex, onSelect, onCancel }: {
    sourceBlockUuidHex: string;
    onSelect: (target: BlockSummaryDto) => void;
    onCancel: () => void;
  } = $props();

  let candidates = $state<BlockSummaryDto[] | null>(null);
  let error = $state<AppError | null>(null);

  // Load the block list once; exclude the source (a same-block move is a no-op
  // the bridge does not guard, so it must never be offered).
  $effect(() => {
    (async () => {
      try {
        const all = await listBlocks();
        candidates = all.filter((b) => !isSameBlock(b.blockUuidHex, sourceBlockUuidHex));
      } catch (e) {
        error = isAppError(e) ? e : { code: 'internal' };
      }
    })();
  });
</script>

<dialog class="move-picker" aria-labelledby="move-picker-title" open>
  <h3 id="move-picker-title" class="move-picker__title">Move to which block?</h3>
  {#if error}
    {@const msg = userMessageFor(error)}
    <p class="move-picker__error" role="alert">{msg.title}</p>
  {:else if candidates === null}
    <p class="move-picker__loading">Loading&#x2026;</p>
  {:else if candidates.length === 0}
    <p class="move-picker__empty">No other blocks to move into.</p>
  {:else}
    <div class="move-picker__list">
      {#each candidates as block (block.blockUuidHex)}
        <button type="button" class="move-picker__target" onclick={() => onSelect(block)}>{block.blockName}</button>
      {/each}
    </div>
  {/if}
  <button type="button" class="move-picker__cancel" onclick={onCancel}>Cancel</button>
</dialog>
