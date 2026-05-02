# Fuzz Monitor — Sparkline & Plateau Dot Strip

**Date:** 2026-05-02
**Author:** Horst Herb (with Claude)
**Status:** Approved — ready for implementation
**Touches:** `core/fuzz/monitor.py`, `core/fuzz/chart.py` (new), `core/fuzz/test_monitor.py`

## Background

The current fuzz monitor card ([core/fuzz/monitor.py](../../../core/fuzz/monitor.py)) shows status, pulse readout, elapsed time, and runs progress as text. The original scaffold spec ([docs/TODO_FUZZ_FOLLOWUP.md §3.2-3.3](../../TODO_FUZZ_FOLLOWUP.md)) deliberately stayed text-only.

Once a campaign is running, the user has no visual cue for two questions the dashboard should answer at a glance:

1. **Is coverage still climbing, or has it flatlined?**
2. **How close are we to the auto-stop plateau condition?**

Plateau is defined by [`check_plateau`](../../../core/fuzz/monitor.py): the last K pulses (default K=10, configurable via `state.plateau_k`) all share the same `cov` AND `corp`.

This design adds two compact visualizations per card:

- A **sparkline** of `cov` over the campaign's pulse history.
- A **plateau dot strip** of K-1 transition dots, where strip-all-grey ⇔ plateau.

## Goals

- Visual answer to "is this campaign still finding things?" in <1s of glance time.
- Visual answer to "how many flat transitions away from plateau?" with the same glance.
- Zero new pip dependencies.
- Pure, deterministic, unit-testable rendering — no browser needed for tests.
- No regression of the existing "both" radio fix or any other behavior.

## Non-goals (YAGNI)

- Hover tooltips on sparkline points.
- Multi-series charts (cov + ft + corp). Cov alone is the primary plateau metric; multi-line at sparkline size is unreadable without a legend.
- Wall-clock X axis. `Pulse` carries no timestamp; index-on-X reads cleanly because libFuzzer pulses come at exec_count = 1, 2, 4, 8, ... so index spacing is a meaningful "progress slots" axis.
- Persistent chart history across runs. Cleared on Start; in-memory only.
- exec_count log-scale X axis.
- Configurable colors / themes.

## Architecture

A new pure module `core/fuzz/chart.py` exposes two functions:

```python
def render_sparkline_svg(values: list[int], width: int, height: int) -> str
def render_plateau_strip_svg(pulses: list[Pulse], k: int, frozen: bool) -> str
```

Both return a self-contained SVG string. Pure: no NiceGUI imports, no globals, no I/O.

In `monitor.py`, `_render_card` adds two `ui.html` placeholder elements between the status line and the pulse readout. The existing `update_card` 1Hz timer calls the renderers each tick and assigns results via `.set_content()`.

### Data flow (per card, per second)

1. Existing 1Hz `ui.timer(update_card)` fires.
2. `effective_sanitizer_key(...)` resolves the radio to the actual `(target, sanitizer)` slot (existing logic — unchanged).
3. `cov_series = [p.cov for p in rs.pulses]` → `render_sparkline_svg(cov_series, 280, 36)` → `sparkline_html.set_content(svg)`.
4. `render_plateau_strip_svg(list(rs.pulses), self.plateau_k, frozen=rs.status != Status.RUNNING)` → `strip_html.set_content(svg)`.
5. When `rs.pulses` is empty, both functions return an empty placeholder SVG (no polyline, no dots) so the card slot reserves space without showing stale data.

The `frozen` flag is passed through but unused for color in this iteration — the dots already speak. Reserved for future "freeze last frame" perf optimisation.

## Card layout

Card order after the change (additions marked NEW):

```
title                                 ← existing
radio (asan / careful / both)         ← existing
runs cap input                        ← existing
status: RUNNING                       ← existing
[━━━━━━━━━━━ sparkline ━━━━━━━━━]     ← NEW (~280×36 px)
○ ○ ○ ● ● ● ● ● ●                     ← NEW dot strip (~280×16 px, K-1 dots)
cov 151 / ft 167 / corp 22 / ...      ← existing pulse readout
elapsed: 06:27                        ← existing
runs: 33.5M                           ← existing
crash label                           ← existing
[Start] [Stop]                        ← existing
```

Rationale: status (badge) is the headline; sparkline + dot strip together are the visual trajectory and plateau-distance signal; numbers are detail beneath.

Card growth: ~52px taller. Cards remain 6-up on a 1080p screen at 3 columns × 2 rows.

## Rendering algorithms

### Sparkline (`render_sparkline_svg(values, width, height)`)

```
1. len(values) == 0 → empty <svg width=W height=H/>
2. len(values) == 1 → <svg> with one <circle cx=W-2 cy=H/2 r=2/>
3. y_min, y_max = min(values), max(values)
4. If y_min == y_max (all flat) → <polyline> at y = H/2
   Else: pad = (y_max - y_min) * 0.10
         y_lo = y_min - pad; y_hi = y_max + pad
5. For each (i, v):
     x = (i / (N-1)) * (W - 2) + 1
     y = H - 1 - ((v - y_lo) / (y_hi - y_lo)) * (H - 2)
6. Emit <polyline points="x1,y1 x2,y2 ..." fill="none"
                  stroke="currentColor" stroke-width="1.5"/>
```

`stroke="currentColor"` so the line inherits the wrapper div's text color (`text-positive` while RUNNING, `text-grey-7` when frozen) — same trick as the existing status badge.

### Plateau dot strip (`render_plateau_strip_svg(pulses, k, frozen)`)

The strip contains **K-1 transition dots**, not K pulse dots. Each dot represents one transition between two consecutive pulses inside the K-pulse plateau window. This makes strip-all-grey ⇔ plateau-condition-met exactly, with no off-by-one between visual and detector.

```
Want K-1 transition dots from the window of last K pulses (newest right):

For i in 0 .. K-2:
  - Need pulses[-(K-1)+i-1] and pulses[-(K-1)+i] to color the dot.
  - If len(pulses) is too short to provide BOTH:
      dot[i] = "empty" (outline only)
  - Else:
      cur  = pulses[-(K-1)+i]
      prev = pulses[-(K-1)+i-1]
      dot[i] = "growth" if cur.cov > prev.cov OR cur.corp > prev.corp
               else "flat"

Layout: dot diameter d=8, gap g=4. Dots laid out left-to-right in width W,
        centered. Height H=16.

Colors:
  growth → fill #16a34a   (Quasar text-positive equivalent)
  flat   → fill #9ca3af   (neutral grey)
  empty  → no fill, stroke #9ca3af width 1
```

A `cov` decrease (libFuzzer doesn't do this, but defensively) is treated as "growth" so the user never sees a misleading "flat" signal from a glitched sample.

## Testing strategy

Both functions are pure → unit-testable via SVG-string parsing without spinning up NiceGUI. New test classes go into `core/fuzz/test_monitor.py` (already imports `Pulse` and `Status`).

### `TestRenderSparklineSvg`

- `test_empty_returns_empty_svg` — `[]` → SVG with no `<polyline>` or `<circle>`.
- `test_single_value_renders_dot` — `[100]` → exactly one `<circle>`.
- `test_two_growing_values` — `[100, 200]` → polyline with 2 points; first y > second y (rising cov = decreasing SVG y).
- `test_flat_values_render_centered_line` — `[100, 100, 100]` → polyline points all at `y = H/2`.
- `test_y_axis_padded_10_percent` — for `[100, 200]`, computed y_lo and y_hi extend 10% beyond min/max so the line doesn't sit flush against an edge.
- `test_x_axis_evenly_spaced` — first x=1, last x=W-1, intermediates evenly spaced.

### `TestRenderPlateauStripSvg`

- `test_empty_pulses_all_outline` — `pulses=[], k=10` → 9 outline circles, no fills.
- `test_partial_history_remaining_outline` — 3 pulses, k=10 → 2 colored transitions on the right, 7 outlines on the left.
- `test_full_growth_window` — 10 pulses with cov strictly increasing → 9 green circles.
- `test_full_plateau_window` — 10 pulses with constant cov+corp → 9 grey filled circles (= plateau).
- `test_one_increase_at_left_boundary` — leftmost transition has growth, rest flat → leftmost dot green, rest grey.
- `test_corp_growth_alone_counts` — cov flat, corp increases → green (matches plateau rule).
- `test_dot_count_equals_k_minus_one` — vary k=2, 5, 10, 20 → dot count is always k-1.

### Integration smoke

One smoke test that doesn't require a browser: instantiate `MonitorApp(["t1"])`, manually populate `app.runs[("t1", "asan")].pulses` with a sequence, then verify both renderers run end-to-end on the live `RunState` without raising. Catches the original "UI calls a key that doesn't exist" bug class.

Tests use `xml.etree.ElementTree.fromstring` to parse SVG output, not regex — so a class change like `<polyline class="..."/>` doesn't break tests.

## Acceptance criteria

1. All existing 100 tests in `test_monitor.py` still pass.
2. ~14 new tests pass (sparkline + dot strip + smoke).
3. Manual: `uv run core/fuzz/monitor.py` → start a campaign → within ~30s sparkline shows a rising line; dot strip shows green dots filling from the right.
4. Manual: campaign reaches plateau → strip becomes all-grey at the same moment status flips to PLATEAU. No off-by-one.
5. Manual: select "both" radio → cards do not KeyError (covered by the prior fix; this design must not regress it).
6. No new pip dependencies in `pyproject.toml` or lockfile.
7. No JS or extra HTTP requests — SVG is inline, payload per tick is ~500 bytes per card.

## Risks

None identified. Inline SVG is universally supported by browsers; NiceGUI's `ui.html` element is a thin DOM passthrough; the renderers are pure and deterministic so snapshot tests are easy.

## Build sequence

1. Add `chart.py` with stub signatures + failing tests for `render_sparkline_svg`. Run, confirm fail.
2. Implement `render_sparkline_svg` to green.
3. Add failing tests for `render_plateau_strip_svg`. Confirm fail.
4. Implement `render_plateau_strip_svg` to green.
5. Wire both into `_render_card` / `update_card` in `monitor.py`. Add integration smoke test.
6. Manual smoke run on a real campaign.
7. Commit.
