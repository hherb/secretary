// Tests for BlockSidebar — the left pane (#526). Replaces the blocks-root
// screen: block list plus the Trash / Contacts destinations plus "New block".

import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import BlockSidebar from '../src/components/BlockSidebar.svelte';
import type { BlockSummaryDto } from '../src/lib/ipc';
import type { SidebarSelection } from '../src/lib/panes';

const BLOCKS: BlockSummaryDto[] = [
  {
    blockUuidHex: 'aaaa1111',
    blockName: 'Banking',
    createdAtMs: 1_700_000_000_000,
    lastModifiedMs: 1_700_000_100_000
  },
  {
    blockUuidHex: 'bbbb2222',
    blockName: 'Work',
    createdAtMs: 1_700_000_000_000,
    lastModifiedMs: 1_700_000_100_000
  }
];

function props(selection: SidebarSelection = { kind: 'none' }, overrides = {}) {
  return {
    blocks: BLOCKS,
    blockCount: BLOCKS.length,
    selection,
    onOpenBlock: () => {},
    onNewBlock: () => {},
    onOpenTrash: () => {},
    onOpenContacts: () => {},
    onTrashBlock: () => {},
    onShareBlock: () => {},
    onRenameBlock: () => {},
    ...overrides
  };
}

describe('BlockSidebar — contents', () => {
  it('lists every block', () => {
    const { getByText } = render(BlockSidebar, { props: props() });
    expect(getByText('Banking')).toBeTruthy();
    expect(getByText('Work')).toBeTruthy();
  });

  it('offers the Trash and Contacts destinations', () => {
    // Exact-string match: onTrashBlock is wired, so every BlockCard also
    // renders a "Trash block" action button. A /trash/i regex would match
    // both that button and this destination's aria-label="Trash", and
    // getByRole throws on multiple matches. Exact string compares the full
    // normalized accessible name, so "Trash block" no longer collides.
    const { getByRole } = render(BlockSidebar, { props: props() });
    expect(getByRole('button', { name: 'Trash' })).toBeTruthy();
    expect(getByRole('button', { name: 'Contacts' })).toBeTruthy();
  });

  it('offers New block', () => {
    const { getByRole } = render(BlockSidebar, { props: props() });
    expect(getByRole('button', { name: /new block/i })).toBeTruthy();
  });

  it('shows the block count', () => {
    const { getByText } = render(BlockSidebar, { props: props() });
    expect(getByText(/2 blocks/i)).toBeTruthy();
  });

  it('singularises the block count', () => {
    const { getByText } = render(BlockSidebar, {
      props: props({ kind: 'none' }, { blocks: [BLOCKS[0]], blockCount: 1 })
    });
    expect(getByText(/1 block(?!s)/i)).toBeTruthy();
  });
});

describe('BlockSidebar — callbacks', () => {
  it('calls onOpenBlock with the clicked block', async () => {
    const onOpenBlock = vi.fn();
    const { getByRole } = render(BlockSidebar, { props: props({ kind: 'none' }, { onOpenBlock }) });
    await fireEvent.click(getByRole('button', { name: /banking/i }));
    expect(onOpenBlock).toHaveBeenCalledWith(BLOCKS[0]);
  });

  it('calls onOpenTrash', async () => {
    const onOpenTrash = vi.fn();
    const { getByRole } = render(BlockSidebar, { props: props({ kind: 'none' }, { onOpenTrash }) });
    await fireEvent.click(getByRole('button', { name: 'Trash' }));
    expect(onOpenTrash).toHaveBeenCalled();
  });

  it('calls onOpenContacts', async () => {
    const onOpenContacts = vi.fn();
    const { getByRole } = render(BlockSidebar, {
      props: props({ kind: 'none' }, { onOpenContacts })
    });
    await fireEvent.click(getByRole('button', { name: 'Contacts' }));
    expect(onOpenContacts).toHaveBeenCalled();
  });

  it('calls onNewBlock', async () => {
    const onNewBlock = vi.fn();
    const { getByRole } = render(BlockSidebar, { props: props({ kind: 'none' }, { onNewBlock }) });
    await fireEvent.click(getByRole('button', { name: /new block/i }));
    expect(onNewBlock).toHaveBeenCalled();
  });
});

describe('BlockSidebar — frozen while an editor is open (#526 review)', () => {
  // Before this branch, blocks were a different screen and a stray sidebar
  // click could never discard an unsaved edit — this freeze restores that
  // property now that the three panes are visible together. The in-handler
  // guard is belt-and-braces alongside `disabled`, because jsdom's
  // fireEvent.click does not respect the `disabled` attribute (same
  // discipline as RecordRow's frozen tests).
  it('does not call onOpenBlock when a block card is clicked', async () => {
    const onOpenBlock = vi.fn();
    const { getByRole } = render(BlockSidebar, {
      props: props({ kind: 'none' }, { onOpenBlock, frozen: true })
    });
    await fireEvent.click(getByRole('button', { name: /banking/i }));
    expect(onOpenBlock).not.toHaveBeenCalled();
  });

  it('does not call onOpenTrash when Trash is clicked', async () => {
    const onOpenTrash = vi.fn();
    const { getByRole } = render(BlockSidebar, {
      props: props({ kind: 'none' }, { onOpenTrash, frozen: true })
    });
    await fireEvent.click(getByRole('button', { name: 'Trash' }));
    expect(onOpenTrash).not.toHaveBeenCalled();
  });

  it('does not call onOpenContacts when Contacts is clicked', async () => {
    const onOpenContacts = vi.fn();
    const { getByRole } = render(BlockSidebar, {
      props: props({ kind: 'none' }, { onOpenContacts, frozen: true })
    });
    await fireEvent.click(getByRole('button', { name: 'Contacts' }));
    expect(onOpenContacts).not.toHaveBeenCalled();
  });

  it('does not call onNewBlock when "+ New block" is clicked', async () => {
    const onNewBlock = vi.fn();
    const { getByRole } = render(BlockSidebar, {
      props: props({ kind: 'none' }, { onNewBlock, frozen: true })
    });
    await fireEvent.click(getByRole('button', { name: /new block/i }));
    expect(onNewBlock).not.toHaveBeenCalled();
  });

  it('disables every control it owns', () => {
    const { getByRole } = render(BlockSidebar, { props: props({ kind: 'none' }, { frozen: true }) });
    expect((getByRole('button', { name: /new block/i }) as HTMLButtonElement).disabled).toBe(true);
    expect((getByRole('button', { name: 'Trash' }) as HTMLButtonElement).disabled).toBe(true);
    expect((getByRole('button', { name: 'Contacts' }) as HTMLButtonElement).disabled).toBe(true);
    expect((getByRole('button', { name: /banking/i }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('remains fully interactive when not frozen', async () => {
    const onOpenBlock = vi.fn();
    const { getByRole } = render(BlockSidebar, {
      props: props({ kind: 'none' }, { onOpenBlock, frozen: false })
    });
    expect((getByRole('button', { name: /banking/i }) as HTMLButtonElement).disabled).toBe(false);
    await fireEvent.click(getByRole('button', { name: /banking/i }));
    expect(onOpenBlock).toHaveBeenCalledWith(BLOCKS[0]);
  });
});

describe('BlockSidebar — selection is reflected for assistive tech', () => {
  it('marks the selected block with aria-current', () => {
    const { getByRole } = render(
      BlockSidebar,
      { props: props({ kind: 'block', blockUuidHex: 'aaaa1111' }) }
    );
    expect(getByRole('button', { name: /banking/i }).getAttribute('aria-current')).toBe('true');
    expect(getByRole('button', { name: /work/i }).getAttribute('aria-current')).toBeNull();
  });

  it('marks the Trash destination when it is the selection', () => {
    const { getByRole } = render(BlockSidebar, { props: props({ kind: 'trash' }) });
    expect(getByRole('button', { name: 'Trash' }).getAttribute('aria-current')).toBe('true');
  });

  it('marks the Contacts destination when it is the selection', () => {
    const { getByRole } = render(BlockSidebar, { props: props({ kind: 'contacts' }) });
    expect(getByRole('button', { name: 'Contacts' }).getAttribute('aria-current')).toBe('true');
  });

  it('marks nothing when the selection is none', () => {
    const { getByRole } = render(BlockSidebar, { props: props({ kind: 'none' }) });
    expect(getByRole('button', { name: /banking/i }).getAttribute('aria-current')).toBeNull();
    expect(getByRole('button', { name: 'Trash' }).getAttribute('aria-current')).toBeNull();
  });
});
