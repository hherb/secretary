<script lang="ts">
  import type { BlockSummaryDto } from '../lib/ipc';
  import { formatShortDate } from '../lib/format';

  // onTrash is optional so browse-only call sites stay unchanged. When
  // supplied, a Trash action sits alongside the navigable card button.
  type Props = {
    block: BlockSummaryDto;
    onClick: (block: BlockSummaryDto) => void;
    onTrash?: (block: BlockSummaryDto) => void;
  };
  let { block, onClick, onTrash }: Props = $props();
</script>

<div class="block-card-wrap">
  <button
    type="button"
    class="block-card"
    aria-label={`Block ${block.blockName}, last modified ${formatShortDate(block.lastModifiedMs)}`}
    onclick={() => onClick(block)}
  >
    <div class="block-card__name">{block.blockName}</div>
    <div class="block-card__meta">modified {formatShortDate(block.lastModifiedMs)}</div>
  </button>

  {#if onTrash}
    <button
      type="button"
      class="block-card__trash"
      aria-label="Trash block"
      onclick={() => onTrash(block)}
    >
      🗑
    </button>
  {/if}
</div>
