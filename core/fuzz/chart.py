"""Pure SVG rendering for the per-card live charts in `monitor.py`.

Two visualizations:
- `render_sparkline_svg` — cov-over-pulse-index polyline, "is the campaign
  still finding things?" at a glance.
- `render_plateau_strip_svg` — K-1 transition dots; strip-all-grey is exactly
  the plateau condition checked by `monitor.check_plateau`.

Pure: no NiceGUI imports, no globals, no I/O. SVG strings are deterministic
given the inputs, which keeps the test surface unit-testable without spinning
up a browser.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from monitor import Pulse


# Quasar `text-positive` (#16a34a) for "still finding things"; neutral grey
# (#9ca3af) for "flat / plateau-eligible". Hex strings rather than CSS classes
# so the SVG is self-contained and tests can assert on color identity without
# pulling Quasar's stylesheet into the test harness.
_DOT_GROWTH_FILL = "#16a34a"
_DOT_FLAT_FILL = "#9ca3af"
_DOT_OUTLINE_STROKE = "#9ca3af"
_DOT_RADIUS = 4
_STRIP_HEIGHT = 16
_STRIP_LEFT_INSET = 8


def render_sparkline_svg(values: list[int], width: int, height: int) -> str:
    """Render a `values` series as an inline SVG polyline of size W×H px.

    X axis is pulse-slot index (uniform spacing), not exec_count or wall-clock
    — libFuzzer's exec_count doubles per pulse, so uniform indexing reads
    cleaner than a true x-quantitative axis at sparkline size.

    Stroke is `currentColor` so the line inherits the parent element's text
    color (the caller flips that between Quasar `text-positive` while RUNNING
    and `text-grey-7` when frozen, mirroring the status badge).

    Edge cases:
    - empty series → bare <svg/> with no children, so the card slot reserves
      space without showing stale data.
    - single sample → one anchor dot at the right edge so the lone pulse
      reads as "newest".
    - all values equal → polyline at vertical centre (no division by zero
      from a zero data range).
    """
    if not values:
        return f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}"></svg>'

    if len(values) == 1:
        cx = width - 2
        cy = height // 2
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">'
            f'<circle cx="{cx}" cy="{cy}" r="2" fill="currentColor"/>'
            f"</svg>"
        )

    n = len(values)
    y_min = min(values)
    y_max = max(values)

    if y_min == y_max:
        # Flat — render a horizontal polyline at vertical centre. Skips the
        # zero-range division and gives the user a clean visual that says
        # "no movement", distinct from the empty / one-sample renders.
        y_centre = height / 2
        pts = [(i / (n - 1) * (width - 2) + 1, y_centre) for i in range(n)]
    else:
        pad = (y_max - y_min) * 0.10
        y_lo = y_min - pad
        y_hi = y_max + pad
        span = y_hi - y_lo
        plot_h = height - 2  # 1px inset top and bottom
        pts = [
            (
                i / (n - 1) * (width - 2) + 1,
                height - 1 - (v - y_lo) / span * plot_h,
            )
            for i, v in enumerate(values)
        ]

    points_attr = " ".join(f"{x:.2f},{y:.2f}" for x, y in pts)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}">'
        f'<polyline points="{points_attr}" fill="none" stroke="currentColor" stroke-width="1.5"/>'
        f"</svg>"
    )


def _dot_cx(i: int, k: int, width: int) -> float:
    """X centre for the i-th dot in a K-1-dot strip of total `width` px.
    Single-dot strip (K=2) is centred; otherwise dots span from inset to
    width-inset with even spacing."""
    n = k - 1
    if n == 1:
        return width / 2
    return _STRIP_LEFT_INSET + i * (width - 2 * _STRIP_LEFT_INSET) / (n - 1)


def render_plateau_strip_svg(
    pulses: "list[Pulse]", k: int, frozen: bool
) -> str:
    """Render the plateau-distance dot strip: K-1 transition dots, newest
    on the right.

    Each dot represents one transition between two consecutive pulses inside
    the last-K-pulse plateau window. A dot is "growth" (filled green) if
    `cov` OR `corp` increased between the pulse pair, "flat" (filled grey)
    if both equal, "outline" (stroke-only) if the pulse pair doesn't exist
    yet (campaign hasn't accumulated K pulses).

    Strip-all-grey ⇔ `check_plateau` returns True for the same window. By
    making this equivalence exact (K-1 transition dots, not K pulse dots)
    the visual cannot disagree with the auto-stop trigger.

    The `frozen` argument is currently unused; reserved for a future
    "freeze last frame" perf optimisation that skips re-rendering once the
    campaign has stopped. Kept in the signature to avoid a breaking change.
    """
    del frozen  # reserved for future use; see docstring

    n = k - 1
    cy = _STRIP_HEIGHT / 2
    parts: list[str] = []
    for i in range(n):
        cx = _dot_cx(i, k, 280)
        # Slot i in the strip <=> transition window[i]→window[i+1] inside
        # the last-K-pulse window. window[i] = pulses[-k+i]; valid only when
        # k - i <= len(pulses).
        needed = k - i
        if needed > len(pulses):
            parts.append(
                f'<circle cx="{cx:.2f}" cy="{cy}" r="{_DOT_RADIUS}" '
                f'fill="none" stroke="{_DOT_OUTLINE_STROKE}" stroke-width="1"/>'
            )
            continue
        prev = pulses[-needed]
        cur = pulses[-needed + 1]
        if cur.cov > prev.cov or cur.corp > prev.corp:
            fill = _DOT_GROWTH_FILL
        else:
            fill = _DOT_FLAT_FILL
        parts.append(
            f'<circle cx="{cx:.2f}" cy="{cy}" r="{_DOT_RADIUS}" fill="{fill}"/>'
        )

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="280" height="{_STRIP_HEIGHT}">'
        + "".join(parts)
        + "</svg>"
    )
