// Tests for PaneShell — the three-column grid and its two splitters (#526).
//
// jsdom has no layout engine, so these assert structure, ARIA and the
// keyboard path (which needs no measurement), not pixel geometry. The drag
// maths itself is unit-tested in paneWidths.test.ts.

import { describe, it, expect } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import { createRawSnippet } from 'svelte';
import PaneShell from '../src/components/PaneShell.svelte';

function textSnippet(text: string) {
  return createRawSnippet(() => ({ render: () => `<span>${text}</span>` }));
}

function renderShell(spanDetail = false) {
  return render(PaneShell, {
    props: {
      sidebar: textSnippet('SIDEBAR'),
      list: textSnippet('LIST'),
      detail: textSnippet('DETAIL'),
      spanDetail
    }
  });
}

describe('PaneShell — structure', () => {
  it('renders all three panes', () => {
    const { getByText } = renderShell();
    expect(getByText('SIDEBAR')).toBeTruthy();
    expect(getByText('LIST')).toBeTruthy();
    expect(getByText('DETAIL')).toBeTruthy();
  });

  it('omits the detail pane when the list spans both columns', () => {
    const { queryByText, getByText } = renderShell(true);
    expect(getByText('LIST')).toBeTruthy();
    expect(queryByText('DETAIL')).toBeNull();
  });
});

describe('PaneShell — splitters are accessible', () => {
  it('exposes two vertical separators', () => {
    const { getAllByRole } = renderShell();
    const separators = getAllByRole('separator');
    expect(separators).toHaveLength(2);
    for (const s of separators) {
      expect(s.getAttribute('aria-orientation')).toBe('vertical');
    }
  });

  it('each separator has a distinguishing accessible name', () => {
    const { getByRole } = renderShell();
    expect(getByRole('separator', { name: /sidebar/i })).toBeTruthy();
    expect(getByRole('separator', { name: /record list/i })).toBeTruthy();
  });

  it('separators are keyboard reachable', () => {
    const { getAllByRole } = renderShell();
    for (const s of getAllByRole('separator')) {
      expect(s.getAttribute('tabindex')).toBe('0');
    }
  });

  it('hides the splitters when the list spans both columns', () => {
    // With no detail pane there is nothing to resize against on the right.
    const { getAllByRole } = renderShell(true);
    expect(getAllByRole('separator')).toHaveLength(1);
  });
});

describe('PaneShell — keyboard resize', () => {
  it('ArrowRight widens the sidebar', async () => {
    const { getByRole, container } = renderShell();
    const shell = container.querySelector('.pane-shell') as HTMLElement;
    const before = shell.style.getPropertyValue('--pane-sidebar-w');
    await fireEvent.keyDown(getByRole('separator', { name: /sidebar/i }), { key: 'ArrowRight' });
    const after = shell.style.getPropertyValue('--pane-sidebar-w');
    expect(after).not.toBe(before);
    expect(parseFloat(after)).toBeGreaterThan(parseFloat(before || '18'));
  });

  it('ArrowLeft narrows the sidebar', async () => {
    const { getByRole, container } = renderShell();
    const shell = container.querySelector('.pane-shell') as HTMLElement;
    const before = parseFloat(shell.style.getPropertyValue('--pane-sidebar-w') || '18');
    await fireEvent.keyDown(getByRole('separator', { name: /sidebar/i }), { key: 'ArrowLeft' });
    const after = parseFloat(shell.style.getPropertyValue('--pane-sidebar-w'));
    expect(after).toBeLessThan(before);
  });

  it('ignores unrelated keys', async () => {
    const { getByRole, container } = renderShell();
    const shell = container.querySelector('.pane-shell') as HTMLElement;
    const before = shell.style.getPropertyValue('--pane-sidebar-w');
    await fireEvent.keyDown(getByRole('separator', { name: /sidebar/i }), { key: 'a' });
    expect(shell.style.getPropertyValue('--pane-sidebar-w')).toBe(before);
  });
});
