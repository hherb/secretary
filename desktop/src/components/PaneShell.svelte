<script lang="ts">
  import type { Snippet } from 'svelte';
  import {
    SIDEBAR_MIN_PX,
    LIST_MIN_PX,
    DETAIL_MIN_PX,
    SPLITTER_PX,
    SPLITTER_COUNT,
    loadFractions,
    saveFraction,
    clampPaneWidthPx,
    paneStorage,
    type PaneKey
  } from '../lib/paneWidths';

  type Props = {
    sidebar: Snippet;
    list: Snippet;
    detail: Snippet;
    /** When true the list occupies both right-hand columns (Trash / Contacts,
        which have no list/detail split of their own) and `detail` is not
        rendered. */
    spanDetail?: boolean;
  };
  let { sidebar, list, detail, spanDetail = false }: Props = $props();

  // Percentage points moved per arrow keypress. Coarse enough to be useful,
  // fine enough to land on a chosen width.
  const KEYBOARD_STEP_PCT = 2;

  // `paneStorage()`, never the bare global: the property access itself throws
  // under a blocked-storage policy, and this runs during component init — an
  // unguarded throw here took down the whole unlocked vault screen (#526
  // review).
  const storage = paneStorage();
  const stored = loadFractions(storage);
  let sidebarPct = $state(stored.sidebar * 100);
  let listPct = $state(stored.list * 100);

  let shellEl = $state<HTMLDivElement | null>(null);
  let dragging = $state<PaneKey | null>(null);

  function containerPx(): number {
    return shellEl?.getBoundingClientRect().width ?? 0;
  }

  /** What the rest of the layout will actually occupy while `pane` is dragged:
      the splitter columns, plus each other pane's effective width.

      The detail pane contributes its FLOOR — it is the `1fr` track, so it
      genuinely does yield down to that. The other fractioned pane contributes
      its CURRENT width, because CSS grid will not shrink it below what its own
      fraction asks for; assuming its floor here is what made the splitter lag
      the cursor (#526 review). Consequence worth knowing: dragging one splitter
      no longer pushes the neighbouring pane — it stops when the neighbour's
      current width would be encroached. Shrink the neighbour first. */
  function reservedPx(pane: PaneKey): number {
    // Spanned (Trash / Contacts): one splitter, and the spanned region keeps
    // the list floor. Only the sidebar splitter is rendered in that layout.
    if (spanDetail) return SPLITTER_PX + LIST_MIN_PX;
    const splitters = SPLITTER_COUNT * SPLITTER_PX;
    return pane === 'sidebar'
      ? splitters + currentPx('list') + DETAIL_MIN_PX
      : splitters + currentPx('sidebar') + DETAIL_MIN_PX;
  }

  /** Commit a pane width given a desired pixel value, clamping against what
      the rest of the layout needs and persisting the resulting fraction. */
  function setPaneFromPx(pane: PaneKey, requestedPx: number): void {
    const width = containerPx();
    if (width <= 0) return;
    const px = clampPaneWidthPx({
      requestedPx,
      ownMinPx: pane === 'sidebar' ? SIDEBAR_MIN_PX : LIST_MIN_PX,
      containerPx: width,
      reservedPx: reservedPx(pane)
    });
    const pct = (px / width) * 100;
    if (pane === 'sidebar') sidebarPct = pct;
    else listPct = pct;
    saveFraction(storage, pane, px / width);
  }

  function currentPx(pane: PaneKey): number {
    return ((pane === 'sidebar' ? sidebarPct : listPct) / 100) * containerPx();
  }

  function onSplitterKeydown(pane: PaneKey, e: KeyboardEvent): void {
    const direction = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    if (direction === 0) return;
    e.preventDefault();
    const width = containerPx();
    // jsdom reports a zero-width container; fall back to a percentage step so
    // the keyboard path stays exercisable in tests and on a not-yet-laid-out
    // first frame.
    if (width <= 0) {
      // Clamped to 0-100: this value feeds aria-valuenow directly, and an
      // out-of-range percentage there would be as incoherent to assistive
      // tech as an out-of-range pixel width would be visually.
      const next = Math.min(
        100,
        Math.max(0, (pane === 'sidebar' ? sidebarPct : listPct) + direction * KEYBOARD_STEP_PCT)
      );
      if (pane === 'sidebar') sidebarPct = next;
      else listPct = next;
      // Persist only a fraction `parseFraction` will accept back. The bounds
      // here are 0 and 100 inclusive, but a stored 0 or 1 is rejected on the
      // next load and silently reset to the default — so a geometry the user
      // deliberately chose would vanish at restart (#526 review).
      if (next > 0 && next < 100) saveFraction(storage, pane, next / 100);
      return;
    }
    setPaneFromPx(pane, currentPx(pane) + direction * (KEYBOARD_STEP_PCT / 100) * width);
  }

  // #526 review — both handlers order their DOM call BEFORE/AFTER the state
  // write deliberately. `setPointerCapture` / `releasePointerCapture` throw
  // (NotFoundError, InvalidStateError) when the pointerId no longer matches an
  // active pointer — which is exactly the `pointercancel` situation the cancel
  // handler below exists for. An exception thrown out of an event handler is
  // swallowed by event dispatch, and a production Tauri build has no console
  // to see it in, so whichever statement runs second may simply never run.
  //
  // Down: capture first, arm `dragging` only if it succeeded — otherwise we'd
  // be armed with no capture, never see the pointerup outside the 5px
  // splitter, and stay armed for the rest of the session.
  function onPointerDown(pane: PaneKey, e: PointerEvent): void {
    try {
      (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
    } catch {
      // No capture, so no drag. Leaving `dragging` null is the safe state.
      return;
    }
    dragging = pane;
  }

  function onPointerMove(e: PointerEvent): void {
    // #526 review — `e.buttons === 0` means no button is currently held. A
    // `pointercancel` (a touch interrupted by a system gesture, or a
    // browser-initiated cancel) is handled below, but this is a second,
    // independent guard: if `dragging` were ever left set by some other
    // path without a matching cancel/up event, a stray hover would resize
    // the pane with no button held at all. Checking both is belt-and-braces
    // for the same reason RecordRow's frozen click guard checks both
    // `disabled` and the handler body.
    if (!dragging || !shellEl || e.buttons === 0) return;
    const left = shellEl.getBoundingClientRect().left;
    // The sidebar splitter sets the sidebar's right edge; the list splitter
    // sets the list's right edge, so the list width is the remainder.
    //
    // Both subtract half a splitter so the divider is CENTRED on the pointer
    // rather than starting at it, and the list additionally subtracts the
    // whole first splitter, which sits between the sidebar and the list. The
    // splitter columns are real grid tracks; ignoring them left the divider a
    // few px behind the cursor for the whole drag (#526 review).
    const half = SPLITTER_PX / 2;
    if (dragging === 'sidebar') {
      setPaneFromPx('sidebar', e.clientX - left - half);
    } else {
      setPaneFromPx('list', e.clientX - left - currentPx('sidebar') - SPLITTER_PX - half);
    }
  }

  // Up / cancel: disarm FIRST, then release. A throwing release must not be
  // able to leave `dragging` set — that is the very stuck-drag this handler
  // was added to prevent, and it would have survived its own fix.
  function onPointerUp(e: PointerEvent): void {
    if (!dragging) return;
    dragging = null;
    try {
      (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId);
    } catch {
      // Already released or the pointer is gone — nothing left to clean up.
    }
  }

  // #526 review — dragging was cleared only on pointerup. A pointercancel
  // (touch interrupted by a system gesture, or a browser-initiated cancel)
  // never fires pointerup, so `dragging` stayed set and a later hover would
  // resize the pane with no button held. Shares onPointerUp's body: same
  // "release capture, clear dragging" cleanup applies to both terminations.
  const onPointerCancel = onPointerUp;
</script>

<div
  class="pane-shell"
  class:pane-shell--spanned={spanDetail}
  bind:this={shellEl}
  style="--pane-sidebar-w: {sidebarPct}%; --pane-list-w: {listPct}%;
    --pane-sidebar-min: {SIDEBAR_MIN_PX}px; --pane-list-min: {LIST_MIN_PX}px;
    --pane-detail-min: {DETAIL_MIN_PX}px; --pane-splitter-w: {SPLITTER_PX}px;"
>
  <div class="pane-shell__sidebar">{@render sidebar()}</div>

  <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
  <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
  <!-- Custom-widget separator: WAI-ARIA has no native interactive element
       for a resizable splitter, so the recommended pattern is `role="separator"`
       (a noninteractive role by default) plus a keyboard handler and
       `tabindex="0"` — exactly what trips this heuristic. A FOCUSABLE
       separator is a widget, not a static divider, so it must also expose
       its current position: aria-valuenow tracks sidebarPct (already
       $state, so this is reactive for free). The min/max are the honest
       0-100 percentage range rather than a computed achievable range —
       the true bounds depend on a container width that isn't measurable
       on the first frame or in jsdom, and a wrong or NaN bound would be
       worse than a wider-than-strictly-true one. -->
  <div
    class="pane-shell__splitter"
    role="separator"
    aria-orientation="vertical"
    aria-label="Resize sidebar"
    aria-valuenow={Math.round(sidebarPct)}
    aria-valuemin="0"
    aria-valuemax="100"
    tabindex="0"
    onkeydown={(e) => onSplitterKeydown('sidebar', e)}
    onpointerdown={(e) => onPointerDown('sidebar', e)}
    onpointermove={onPointerMove}
    onpointerup={onPointerUp}
    onpointercancel={onPointerCancel}
  ></div>

  <div class="pane-shell__list">{@render list()}</div>

  {#if !spanDetail}
    <!-- svelte-ignore a11y_no_noninteractive_tabindex -->
    <!-- svelte-ignore a11y_no_noninteractive_element_interactions -->
    <!-- See the sidebar splitter above for why aria-valuenow/min/max are here. -->
    <div
      class="pane-shell__splitter"
      role="separator"
      aria-orientation="vertical"
      aria-label="Resize record list"
      aria-valuenow={Math.round(listPct)}
      aria-valuemin="0"
      aria-valuemax="100"
      tabindex="0"
      onkeydown={(e) => onSplitterKeydown('list', e)}
      onpointerdown={(e) => onPointerDown('list', e)}
      onpointermove={onPointerMove}
      onpointerup={onPointerUp}
      onpointercancel={onPointerCancel}
    ></div>

    <div class="pane-shell__detail">{@render detail()}</div>
  {/if}
</div>

<style>
  .pane-shell {
    display: grid;
    /* Floors come from --pane-*-min, set inline from paneWidths.ts's
       SIDEBAR_MIN_PX / LIST_MIN_PX / DETAIL_MIN_PX (#526 review) — CSS can't
       import a TS constant, so this keeps paneWidths.ts the single source
       instead of the same three numbers being hand-copied here too, where
       they could silently drift from the drag clamp. */
    grid-template-columns:
      minmax(var(--pane-sidebar-min), var(--pane-sidebar-w))
      auto
      minmax(var(--pane-list-min), var(--pane-list-w))
      auto
      minmax(var(--pane-detail-min), 1fr);
    height: 100%;
    min-height: 0;
    overflow: hidden;
  }

  /* Trash / Contacts: sidebar, one splitter, then everything else. */
  .pane-shell--spanned {
    grid-template-columns: minmax(var(--pane-sidebar-min), var(--pane-sidebar-w)) auto 1fr;
  }

  .pane-shell__sidebar,
  .pane-shell__list,
  .pane-shell__detail {
    min-width: 0;
    min-height: 0;
    overflow-y: auto;
  }

  .pane-shell__sidebar {
    background: var(--color-bg);
  }

  .pane-shell__list,
  .pane-shell__detail {
    background: var(--color-bg-elevated);
  }

  .pane-shell__splitter {
    /* From paneWidths.ts's SPLITTER_PX — the same single-source discipline the
       floors use. This width is a TERM in MIN_SHELL_WIDTH_PX, so a hand-copied
       number here would silently invalidate the window's minWidth. */
    width: var(--pane-splitter-w);
    cursor: col-resize;
    background: var(--color-border);
    /* Widen the hit area without widening the visual line. */
    background-clip: content-box;
    border-inline: 2px solid transparent;
  }

  .pane-shell__splitter:hover,
  .pane-shell__splitter:focus-visible {
    background-color: var(--color-primary);
    outline: none;
  }
</style>
