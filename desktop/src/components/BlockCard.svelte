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
    /** #526 review — an editor is open in the detail pane; this card goes
        non-interactive, mirroring RecordRow's frozen treatment, so a stray
        click cannot silently discard an unsaved edit. */
    frozen?: boolean;
  };
  let {
    block,
    onClick,
    onTrash,
    onShare,
    onRename,
    selected = false,
    frozen = false
  }: Props = $props();
</script>

<div
  class="block-card-wrap"
  class:block-card-wrap--selected={selected}
  class:block-card-wrap--frozen={frozen}
>
  <button
    type="button"
    class="block-card"
    aria-label={`Block ${block.blockName}, last modified ${formatShortDate(block.lastModifiedMs)}`}
    aria-current={selected ? 'true' : undefined}
    disabled={frozen}
    onclick={() => {
      if (!frozen) onClick(block);
    }}
  >
    <div class="block-card__name">{block.blockName}</div>
    <div class="block-card__meta">modified {formatShortDate(block.lastModifiedMs)}</div>
  </button>

  {#if !frozen}
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

  /* #526 review — selection previously drove only aria-current and the
     action reveal, with no visible highlight at all: internally
     inconsistent with .block-sidebar__destination[aria-current='true'],
     which DOES paint one. Same fill RecordRow.svelte uses for its selected
     row, for the same reason: the button (.block-card) paints its own
     opaque background, so the fill has to land there, not on the wrap. */
  .block-card-wrap--selected .block-card {
    background: var(--color-primary);
    border-color: var(--color-primary);
  }

  .block-card-wrap--selected .block-card__name,
  .block-card-wrap--selected .block-card__meta {
    color: var(--color-on-primary);
  }

  /* Frozen: an editor is open. Dimmed and non-interactive, mirroring
     RecordRow's frozen treatment so the two panes read consistently. */
  .block-card-wrap--frozen {
    opacity: 0.45;
    pointer-events: none;
  }
</style>
