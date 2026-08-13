// Tests for PaneShell — the three-column grid and its two splitters (#526).
//
// jsdom has no layout engine, so these assert structure, ARIA and the
// keyboard path (which needs no measurement), not pixel geometry. The drag
// maths itself is unit-tested in paneWidths.test.ts.

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import { createRawSnippet } from 'svelte';
import PaneShell from '../src/components/PaneShell.svelte';
import { LIST_DEFAULT_FRACTION, DETAIL_MIN_PX, SPLITTER_PX, SPLITTER_COUNT } from '../src/lib/paneWidths';

// PaneShell reads AND writes the real localStorage, so without this every test
// here inherits whatever geometry its predecessors persisted. That was a
// latent order-dependency, not a theoretical one: the 60-press clamp test
// below leaves the stored fraction at "0"/"1", and it passed only because it
// happened to run last — `parseFraction` rejects those on the next load, so a
// reordered file would have failed a sibling test for no real reason
// (#526 review).
beforeEach(() => localStorage.clear());

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

  it('exposes aria-valuenow reflecting the pane width, and it updates on resize', async () => {
    // A FOCUSABLE separator is a widget under WAI-ARIA, not a static
    // divider, so it must expose its current position (#526 review). Derive
    // the expected value from the rendered CSS var rather than hardcoding a
    // default percentage, since localStorage state can carry over between
    // tests in this file.
    const { getByRole, container } = renderShell();
    const shell = container.querySelector('.pane-shell') as HTMLElement;
    const separator = getByRole('separator', { name: /sidebar/i });

    const initialPct = parseFloat(shell.style.getPropertyValue('--pane-sidebar-w'));
    expect(separator.getAttribute('aria-valuenow')).toBe(String(Math.round(initialPct)));
    expect(separator.getAttribute('aria-valuemin')).toBe('0');
    expect(separator.getAttribute('aria-valuemax')).toBe('100');

    await fireEvent.keyDown(separator, { key: 'ArrowRight' });
    const afterPct = parseFloat(shell.style.getPropertyValue('--pane-sidebar-w'));
    expect(separator.getAttribute('aria-valuenow')).toBe(String(Math.round(afterPct)));
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

  it('the list splitter resizes the LIST, not the sidebar', async () => {
    // Every other keyboard test drives the sidebar separator, so a copy-paste
    // of `onSplitterKeydown('sidebar', e)` or `aria-valuenow={sidebarPct}`
    // onto the list splitter would have gone unnoticed: keyboard-resizing the
    // list would silently move the sidebar and screen readers would announce
    // the wrong position (#526 review).
    const { getByRole, container } = renderShell();
    const shell = container.querySelector('.pane-shell') as HTMLElement;
    const listSplitter = getByRole('separator', { name: /record list/i });
    const sidebarBefore = shell.style.getPropertyValue('--pane-sidebar-w');
    const listBefore = parseFloat(shell.style.getPropertyValue('--pane-list-w'));

    await fireEvent.keyDown(listSplitter, { key: 'ArrowRight' });

    expect(parseFloat(shell.style.getPropertyValue('--pane-list-w'))).toBeGreaterThan(listBefore);
    expect(shell.style.getPropertyValue('--pane-sidebar-w')).toBe(sidebarBefore);
  });

  it('each splitter reports its OWN position via aria-valuenow', async () => {
    const { getByRole, container } = renderShell();
    const shell = container.querySelector('.pane-shell') as HTMLElement;
    await fireEvent.keyDown(getByRole('separator', { name: /record list/i }), {
      key: 'ArrowRight'
    });
    const listPct = parseFloat(shell.style.getPropertyValue('--pane-list-w'));
    const sidebarPct = parseFloat(shell.style.getPropertyValue('--pane-sidebar-w'));
    expect(getByRole('separator', { name: /record list/i }).getAttribute('aria-valuenow')).toBe(
      String(Math.round(listPct))
    );
    expect(getByRole('separator', { name: /sidebar/i }).getAttribute('aria-valuenow')).toBe(
      String(Math.round(sidebarPct))
    );
  });

  it('keeps aria-valuenow within 0-100 under many repeated presses in the zero-width (jsdom) path', async () => {
    // jsdom always reports a zero-width container, so every keydown here
    // takes onSplitterKeydown's fallback percentage-step branch — the one
    // the #526 review found unclamped. 60 presses (120 percentage points)
    // overshoots either bound from any starting percentage, in both
    // directions, so the exact 0 / 100 landing proves the clamp rather than
    // merely "didn't blow up".
    const { getByRole } = renderShell();
    const separator = getByRole('separator', { name: /sidebar/i });

    for (let i = 0; i < 60; i++) {
      await fireEvent.keyDown(separator, { key: 'ArrowLeft' });
    }
    expect(Number(separator.getAttribute('aria-valuenow'))).toBe(0);

    for (let i = 0; i < 60; i++) {
      await fireEvent.keyDown(separator, { key: 'ArrowRight' });
    }
    expect(Number(separator.getAttribute('aria-valuenow'))).toBe(100);
  });
});

// ---------------------------------------------------------------------------
// Pointer drag (#526 review)
//
// This whole path had NO test. Two of its behaviours were added by the #526
// review itself — the `e.buttons === 0` guard and the `pointercancel`
// handler — and nothing prevented their removal.
//
// A naive pointer test here would be VACUOUS: jsdom reports
// getBoundingClientRect().width === 0, so `setPaneFromPx` early-returns and
// the assertions pass whether or not the guards exist. Stubbing the rect is
// what makes these tests able to fail.
const CONTAINER_PX = 1200;

// jsdom does not implement PointerEvent, so `fireEvent.pointerMove(el, {
// clientX, buttons })` silently DROPS both properties — the handler then sees
// `undefined`, `e.buttons === 0` is false, and `e.clientX - left` is NaN. A
// test written the obvious way therefore fails for a reason that has nothing
// to do with the component. MouseEvent carries both, and the handlers only
// ever read `clientX` / `buttons` / `currentTarget` / `pointerId` (the last
// only to hand to the capture mocks), so a MouseEvent with a pointer type
// name exercises the real code path.
function firePointer(
  el: Element,
  type: 'pointerdown' | 'pointermove' | 'pointerup' | 'pointercancel',
  init: { clientX?: number; buttons?: number } = {}
) {
  return fireEvent(el, new MouseEvent(type, { bubbles: true, cancelable: true, ...init }));
}

function stubLayout() {
  return vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockReturnValue({
    width: CONTAINER_PX,
    height: 800,
    left: 0,
    top: 0,
    right: CONTAINER_PX,
    bottom: 800,
    x: 0,
    y: 0,
    toJSON: () => ({})
  } as DOMRect);
}

describe('PaneShell — pointer drag', () => {
  let rect: ReturnType<typeof stubLayout>;

  beforeEach(() => {
    // jsdom implements neither method; the component calls both.
    HTMLElement.prototype.setPointerCapture = vi.fn();
    HTMLElement.prototype.releasePointerCapture = vi.fn();
    rect = stubLayout();
  });

  afterEach(() => rect.mockRestore());

  function sidebarPctOf(container: HTMLElement): number {
    const shell = container.querySelector('.pane-shell') as HTMLElement;
    return parseFloat(shell.style.getPropertyValue('--pane-sidebar-w'));
  }

  it('a drag moves the sidebar splitter to the pointer', async () => {
    const { getByRole, container } = renderShell();
    const splitter = getByRole('separator', { name: /sidebar/i });

    await firePointer(splitter, 'pointerdown', { buttons: 1 });
    await firePointer(splitter, 'pointermove', { buttons: 1, clientX: 400 });

    // The splitter is CENTRED on the pointer, so the sidebar's right edge sits
    // half a splitter left of clientX. Without that term the divider trails the
    // cursor for the whole drag.
    const expectedPx = 400 - SPLITTER_PX / 2;
    expect(sidebarPctOf(container)).toBeCloseTo((expectedPx / CONTAINER_PX) * 100, 5);
  });

  it('a hover with no button held does not resize', async () => {
    // Pins the `e.buttons === 0` guard. Without it, any mouse movement over
    // the splitter after a lost pointerup would silently resize AND persist.
    const { getByRole, container } = renderShell();
    const splitter = getByRole('separator', { name: /sidebar/i });

    await firePointer(splitter, 'pointerdown', { buttons: 1 });
    const before = sidebarPctOf(container);
    await firePointer(splitter, 'pointermove', { buttons: 0, clientX: 700 });

    expect(sidebarPctOf(container)).toBe(before);
  });

  it('pointercancel ends the drag, so a later move is inert', async () => {
    // The regression the #526 review fixed: `dragging` was cleared only on
    // pointerup, and a pointercancel (touch pre-empted by a system gesture)
    // never fires one — leaving the pane resizing under a plain hover.
    const { getByRole, container } = renderShell();
    const splitter = getByRole('separator', { name: /sidebar/i });

    await firePointer(splitter, 'pointerdown', { buttons: 1 });
    await firePointer(splitter, 'pointermove', { buttons: 1, clientX: 400 });
    const afterDrag = sidebarPctOf(container);

    await firePointer(splitter, 'pointercancel');
    await firePointer(splitter, 'pointermove', { buttons: 1, clientX: 700 });

    expect(sidebarPctOf(container)).toBe(afterDrag);
  });

  it('pointerup ends the drag', async () => {
    const { getByRole, container } = renderShell();
    const splitter = getByRole('separator', { name: /sidebar/i });

    await firePointer(splitter, 'pointerdown', { buttons: 1 });
    await firePointer(splitter, 'pointermove', { buttons: 1, clientX: 400 });
    const afterDrag = sidebarPctOf(container);

    await firePointer(splitter, 'pointerup');
    await firePointer(splitter, 'pointermove', { buttons: 1, clientX: 700 });

    expect(sidebarPctOf(container)).toBe(afterDrag);
  });

  it('a throwing releasePointerCapture still ends the drag', async () => {
    // The ordering fix: release used to run BEFORE `dragging = null`, and it
    // throws NotFoundError in exactly the pointercancel case this handler
    // exists for. An exception out of an event handler is swallowed by
    // dispatch, so the stuck drag survived its own fix (#526 review).
    HTMLElement.prototype.releasePointerCapture = vi.fn(() => {
      throw new DOMException('NotFoundError');
    });
    const { getByRole, container } = renderShell();
    const splitter = getByRole('separator', { name: /sidebar/i });

    await firePointer(splitter, 'pointerdown', { buttons: 1 });
    await firePointer(splitter, 'pointermove', { buttons: 1, clientX: 400 });
    const afterDrag = sidebarPctOf(container);

    await firePointer(splitter, 'pointercancel');
    await firePointer(splitter, 'pointermove', { buttons: 1, clientX: 700 });

    expect(sidebarPctOf(container)).toBe(afterDrag);
  });

  it('a failed setPointerCapture does not arm a captureless drag', async () => {
    // Armed-with-no-capture means we never see the pointerup outside the 5px
    // splitter, so `dragging` would stay set for the rest of the session.
    HTMLElement.prototype.setPointerCapture = vi.fn(() => {
      throw new DOMException('NotFoundError');
    });
    const { getByRole, container } = renderShell();
    const splitter = getByRole('separator', { name: /sidebar/i });
    const before = sidebarPctOf(container);

    await firePointer(splitter, 'pointerdown', { buttons: 1 });
    await firePointer(splitter, 'pointermove', { buttons: 1, clientX: 700 });

    expect(sidebarPctOf(container)).toBe(before);
  });

  it('the drag stops where the layout stops, leaving room for the siblings', async () => {
    // The clamp reserves the splitters plus the list's CURRENT width plus the
    // detail floor, so the committed width is one the grid can actually
    // render. Dragging far past that must not hand back a phantom width.
    const { getByRole, container } = renderShell();
    const splitter = getByRole('separator', { name: /sidebar/i });

    await firePointer(splitter, 'pointerdown', { buttons: 1 });
    await firePointer(splitter, 'pointermove', { buttons: 1, clientX: 9999 });

    const listPx = LIST_DEFAULT_FRACTION * CONTAINER_PX;
    const expectedPx =
      CONTAINER_PX - SPLITTER_COUNT * SPLITTER_PX - listPx - DETAIL_MIN_PX;
    expect(sidebarPctOf(container)).toBeCloseTo((expectedPx / CONTAINER_PX) * 100, 5);
    // And everything still fits.
    const sidebarPx = (sidebarPctOf(container) / 100) * CONTAINER_PX;
    expect(sidebarPx + listPx + DETAIL_MIN_PX + SPLITTER_COUNT * SPLITTER_PX).toBeLessThanOrEqual(
      CONTAINER_PX
    );
  });
});
