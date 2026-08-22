<script lang="ts">
  import type { BlockSummaryDto } from '../lib/ipc';
  import { formatShortDate } from '../lib/format';
  import Link from './icons/Link.svelte';
  import Pencil from './icons/Pencil.svelte';
  import Trash from './icons/Trash.svelte';

  // onTrash / onShare / onRename are optional so browse-only call sites stay unchanged.
  // When supplied, each renders an action alongside the navigable card button.
  type Props = {
    block: BlockSummaryDto;
    onClick: (block: BlockSummaryDto) => void;
    onTrash?: (block: BlockSummaryDto) => void;
    onShare?: (block: BlockSummaryDto) => void;
    onRename?: (block: BlockSummaryDto) => void;
    /** #526 — sidebar selection. Drives aria-current and the visual highlight. */
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
    <!-- #526 review (GUI pass) — actions live in their own container so they
         can leave the flow. They are hidden with `opacity: 0` rather than
         `display: none`, deliberately: an opacity-hidden control stays
         focusable and stays in the accessibility tree, so a keyboard user can
         still tab to it (`:focus-within` below reveals the group). But an
         opacity-hidden element KEEPS ITS LAYOUT BOX — so as flex siblings of
         the card these three permanently reserved their width, hover or not.
         In a ~230px sidebar that overflowed the pane and produced a
         horizontal scrollbar. Absolutely positioning the group is what makes
         "hidden" actually cost nothing. -->
    <div class="block-card__actions">
      {#if onRename}
        <button
          type="button"
          class="block-card__rename"
          aria-label="Rename block"
          title="Rename block"
          onclick={() => onRename(block)}
        >
          <Pencil size={17} />
        </button>
      {/if}

      {#if onShare}
        <button
          type="button"
          class="block-card__share"
          aria-label="Share block"
          title="Share block"
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
          title="Move block to Trash"
          onclick={() => onTrash(block)}
        >
          <Trash />
        </button>
      {/if}
    </div>
  {/if}
</div>

<style>
  /* #526 — three action buttons do not fit a sidebar column. Reveal them on
     hover or when anything inside the row has keyboard focus.
     Opacity only: the buttons stay in the DOM and in the accessibility tree,
     because a keyboard user never hovers. */
  /* The card owns the full column width; the actions float over its right
     edge instead of sitting beside it (see the markup comment above). Each
     button already paints an opaque --color-bg-elevated background and a
     border, so the group occludes any long block name it overlaps rather
     than colliding with it. */
  .block-card__actions {
    position: absolute;
    inset-block-start: 50%;
    inset-inline-end: var(--space-2);
    translate: 0 -50%;
    display: flex;
    align-items: center;
    gap: var(--space-2);
    opacity: 0;
    transition: opacity 120ms ease;
  }

  .block-card-wrap:hover .block-card__actions,
  .block-card-wrap:focus-within .block-card__actions {
    opacity: 1;
  }

  @media (prefers-reduced-motion: reduce) {
    .block-card__actions {
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
