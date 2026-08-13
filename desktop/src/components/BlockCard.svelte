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
    /** #526 — sidebar selection. Drives aria-current and keeps the row's
        actions visible without a hover. */
    selected?: boolean;
  };
  let { block, onClick, onTrash, onShare, onRename, selected = false }: Props = $props();
</script>

<div class="block-card-wrap" class:block-card-wrap--selected={selected}>
  <button
    type="button"
    class="block-card"
    aria-label={`Block ${block.blockName}, last modified ${formatShortDate(block.lastModifiedMs)}`}
    aria-current={selected ? 'true' : undefined}
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

<style>
  /* #526 — three action buttons do not fit a sidebar column. Reveal them on
     hover, on selection, or when anything inside the row has keyboard focus.
     Opacity only: the buttons stay in the DOM and in the accessibility tree,
     because a keyboard user never hovers. */
  .block-card-wrap :global(.block-card__rename),
  .block-card-wrap :global(.block-card__share),
  .block-card-wrap :global(.block-card__trash) {
    opacity: 0;
    transition: opacity 120ms ease;
  }

  .block-card-wrap:hover :global(.block-card__rename),
  .block-card-wrap:hover :global(.block-card__share),
  .block-card-wrap:hover :global(.block-card__trash),
  .block-card-wrap:focus-within :global(.block-card__rename),
  .block-card-wrap:focus-within :global(.block-card__share),
  .block-card-wrap:focus-within :global(.block-card__trash),
  .block-card-wrap--selected :global(.block-card__rename),
  .block-card-wrap--selected :global(.block-card__share),
  .block-card-wrap--selected :global(.block-card__trash) {
    opacity: 1;
  }

  @media (prefers-reduced-motion: reduce) {
    .block-card-wrap :global(.block-card__rename),
    .block-card-wrap :global(.block-card__share),
    .block-card-wrap :global(.block-card__trash) {
      transition: none;
    }
  }
</style>
