<script lang="ts">
  import type { Snippet } from 'svelte';
  import {
    SIDEBAR_MIN_PX,
    LIST_MIN_PX,
    DETAIL_MIN_PX,
    loadFractions,
    saveFraction,
    clampPaneWidthPx,
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

  const stored = loadFractions(localStorage);
  let sidebarPct = $state(stored.sidebar * 100);
  let listPct = $state(stored.list * 100);

  let shellEl = $state<HTMLDivElement | null>(null);
  let dragging = $state<PaneKey | null>(null);

  function containerPx(): number {
    return shellEl?.getBoundingClientRect().width ?? 0;
  }

  /** Commit a pane width given a desired pixel value, clamping against the
      other panes' floors and persisting the resulting fraction. */
  function setPaneFromPx(pane: PaneKey, requestedPx: number): void {
    const width = containerPx();
    if (width <= 0) return;
    const px = clampPaneWidthPx({
      requestedPx,
      ownMinPx: pane === 'sidebar' ? SIDEBAR_MIN_PX : LIST_MIN_PX,
      containerPx: width,
      siblingsMinPx:
        pane === 'sidebar' ? LIST_MIN_PX + DETAIL_MIN_PX : SIDEBAR_MIN_PX + DETAIL_MIN_PX
    });
    const pct = (px / width) * 100;
    if (pane === 'sidebar') sidebarPct = pct;
    else listPct = pct;
    saveFraction(localStorage, pane, px / width);
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
      saveFraction(localStorage, pane, next / 100);
      return;
    }
    setPaneFromPx(pane, currentPx(pane) + direction * (KEYBOARD_STEP_PCT / 100) * width);
  }

  function onPointerDown(pane: PaneKey, e: PointerEvent): void {
    dragging = pane;
    (e.currentTarget as HTMLElement).setPointerCapture(e.pointerId);
  }

  function onPointerMove(e: PointerEvent): void {
    if (!dragging || !shellEl) return;
    const left = shellEl.getBoundingClientRect().left;
    // The sidebar splitter sets the sidebar's right edge; the list splitter
    // sets the list's right edge, so the list width is the remainder.
    if (dragging === 'sidebar') setPaneFromPx('sidebar', e.clientX - left);
    else setPaneFromPx('list', e.clientX - left - currentPx('sidebar'));
  }

  function onPointerUp(e: PointerEvent): void {
    if (!dragging) return;
    (e.currentTarget as HTMLElement).releasePointerCapture(e.pointerId);
    dragging = null;
  }
</script>

<div
  class="pane-shell"
  class:pane-shell--spanned={spanDetail}
  bind:this={shellEl}
  style="--pane-sidebar-w: {sidebarPct}%; --pane-list-w: {listPct}%;"
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
    ></div>

    <div class="pane-shell__detail">{@render detail()}</div>
  {/if}
</div>

<style>
  .pane-shell {
    display: grid;
    grid-template-columns:
      minmax(180px, var(--pane-sidebar-w))
      auto
      minmax(260px, var(--pane-list-w))
      auto
      minmax(320px, 1fr);
    height: 100%;
    min-height: 0;
    overflow: hidden;
  }

  /* Trash / Contacts: sidebar, one splitter, then everything else. */
  .pane-shell--spanned {
    grid-template-columns: minmax(180px, var(--pane-sidebar-w)) auto 1fr;
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
    width: 5px;
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
