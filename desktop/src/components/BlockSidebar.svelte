<script lang="ts">
  import type { BlockSummaryDto } from '../lib/ipc';
  import type { SidebarSelection } from '../lib/panes';
  import BlockCard from './BlockCard.svelte';
  import Trash from './icons/Trash.svelte';
  import Users from './icons/Users.svelte';

  type Props = {
    blocks: BlockSummaryDto[];
    blockCount: number;
    selection: SidebarSelection;
    onOpenBlock: (block: BlockSummaryDto) => void;
    onNewBlock: () => void;
    onOpenTrash: () => void;
    onOpenContacts: () => void;
    onTrashBlock: (block: BlockSummaryDto) => void;
    onShareBlock: (block: BlockSummaryDto) => void;
    onRenameBlock: (block: BlockSummaryDto) => void;
  };
  let {
    blocks,
    blockCount,
    selection,
    onOpenBlock,
    onNewBlock,
    onOpenTrash,
    onOpenContacts,
    onTrashBlock,
    onShareBlock,
    onRenameBlock
  }: Props = $props();

  function isSelectedBlock(block: BlockSummaryDto): boolean {
    return selection.kind === 'block' && selection.blockUuidHex === block.blockUuidHex;
  }
</script>

<nav class="block-sidebar" aria-label="Vault blocks">
  <button type="button" class="block-sidebar__new" onclick={onNewBlock}>+ New block</button>

  <div class="block-sidebar__count">
    {blockCount} block{blockCount === 1 ? '' : 's'}
  </div>

  <div class="block-sidebar__blocks">
    {#each blocks as block (block.blockUuidHex)}
      <BlockCard
        {block}
        selected={isSelectedBlock(block)}
        onClick={onOpenBlock}
        onTrash={onTrashBlock}
        onShare={onShareBlock}
        onRename={onRenameBlock}
      />
    {/each}
  </div>

  <div class="block-sidebar__destinations">
    <!-- Explicit aria-label (rather than relying on the text content "Trash"
         alongside the icon) so this button's accessible name stays exactly
         "Trash" — every BlockCard row above also renders a "Trash block"
         action once onTrashBlock is wired, and a looser name here would
         collide with those under a substring/regex query (#526). -->
    <button
      type="button"
      class="block-sidebar__destination"
      aria-label="Trash"
      aria-current={selection.kind === 'trash' ? 'true' : undefined}
      onclick={onOpenTrash}
    >
      <Trash />Trash
    </button>
    <button
      type="button"
      class="block-sidebar__destination"
      aria-label="Contacts"
      aria-current={selection.kind === 'contacts' ? 'true' : undefined}
      onclick={onOpenContacts}
    >
      <Users />Contacts
    </button>
  </div>
</nav>

<style>
  .block-sidebar {
    display: flex;
    flex-direction: column;
    gap: var(--space-2);
    padding: var(--space-3);
    height: 100%;
    min-height: 0;
  }

  .block-sidebar__count {
    font-size: var(--font-size-xs);
    color: var(--color-text-muted);
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }

  .block-sidebar__blocks {
    flex: 1;
    min-height: 0;
    overflow-y: auto;
  }

  /* Destinations pin to the bottom, away from the block list they are not
     part of. */
  .block-sidebar__destinations {
    display: flex;
    flex-direction: column;
    gap: var(--space-1);
    padding-top: var(--space-2);
    border-top: 1px solid var(--color-border);
  }

  .block-sidebar__destination {
    display: flex;
    align-items: center;
    gap: var(--space-2);
    padding: var(--space-2);
    border: none;
    border-radius: var(--radius-sm);
    background: none;
    color: var(--color-text);
    font-size: var(--font-size-sm);
    text-align: left;
    cursor: pointer;
  }

  .block-sidebar__destination:hover {
    background: var(--color-bg-elevated);
  }

  .block-sidebar__destination[aria-current='true'] {
    background: var(--color-bg-elevated);
    color: var(--color-primary);
    font-weight: 600;
  }
</style>
