<script lang="ts">
  import type { BlockSummaryDto } from '../lib/ipc';
  import { formatShortDate } from '../lib/format';
  import Link from './icons/Link.svelte';
  import Trash from './icons/Trash.svelte';

  // onTrash / onShare / onRename are optional so browse-only call sites stay unchanged.
  // When supplied, each renders an action alongside the navigable card button.
  type Props = {
    block: BlockSummaryDto;
    onClick: (block: BlockSummaryDto) => void;
    onTrash?: (block: BlockSummaryDto) => void;
    onShare?: (block: BlockSummaryDto) => void;
    onRename?: (block: BlockSummaryDto) => void;
  };
  let { block, onClick, onTrash, onShare, onRename }: Props = $props();
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

  {#if onRename}
    <button
      type="button"
      class="block-card__rename"
      aria-label="Rename block"
      onclick={() => onRename(block)}
    >
      Rename
    </button>
  {/if}

  {#if onShare}
    <button
      type="button"
      class="block-card__share"
      aria-label="Share block"
      onclick={() => onShare(block)}
    >
      <Link />
    </button>
  {/if}

  {#if onTrash}
    <button
      type="button"
      class="block-card__trash"
      aria-label="Trash block"
      onclick={() => onTrash(block)}
    >
      <Trash />
    </button>
  {/if}
</div>
