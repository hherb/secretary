"""Unit tests for `monitor.py` pure functions.

Run from the repo root:
    uv run --with pytest pytest core/fuzz/test_monitor.py -v
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

import pytest

from chart import render_plateau_strip_svg, render_sparkline_svg
from monitor import (
    Pulse,
    RunState,
    Status,
    aggregate_artifact_counts,
    build_subprocess_env,
    categorize_artifact,
    check_plateau,
    effective_sanitizer_key,
    find_nightly_toolchain,
    format_card_elapsed,
    format_elapsed,
    format_findings_summary,
    format_human_count,
    format_pulse_readout,
    format_runs_progress,
    parse_pulse_line,
    parse_runs_cap,
    parse_targets,
    status_badge_class,
)


class TestParsePulseLine:
    def test_pulse_typical(self):
        line = "#1048576\tpulse  cov: 1247 ft: 2891 corp: 142/8.2k exec/s: 58000 rss: 124Mb"
        p = parse_pulse_line(line)
        assert p == Pulse(exec_count=1048576, cov=1247, ft=2891, corp=142, exec_s=58000, rss=124)

    def test_done_with_lim(self):
        line = "#1000\tDONE   cov: 714 ft: 978 corp: 61/147b lim: 4 exec/s: 0 rss: 46Mb"
        p = parse_pulse_line(line)
        assert p == Pulse(exec_count=1000, cov=714, ft=978, corp=61, exec_s=0, rss=46)

    def test_new_event(self):
        line = "#2000000\tNEW    cov: 80 ft: 80 corp: 4/15b exec/s: 60606 rss: 803Mb"
        p = parse_pulse_line(line)
        assert p == Pulse(exec_count=2000000, cov=80, ft=80, corp=4, exec_s=60606, rss=803)

    def test_inited(self):
        line = "#3\tINITED cov: 234 ft: 234 corp: 1/3989b exec/s: 0 rss: 41Mb"
        p = parse_pulse_line(line)
        assert p == Pulse(exec_count=3, cov=234, ft=234, corp=1, exec_s=0, rss=41)

    def test_corp_size_with_kilo_suffix(self):
        line = "#16777216\tpulse  cov: 8500 ft: 14200 corp: 350/1.2Mb exec/s: 12500 rss: 256Mb"
        p = parse_pulse_line(line)
        assert p.corp == 350
        assert p.exec_count == 16777216

    def test_non_pulse_line_returns_none(self):
        assert parse_pulse_line("Done 100000 runs in 1 second(s)") is None
        assert parse_pulse_line("INFO: Loaded 1 modules") is None
        assert parse_pulse_line("") is None

    def test_malformed_line_returns_none(self):
        assert parse_pulse_line("#abc\tpulse cov: bad") is None
        assert parse_pulse_line("#100\tpulse cov: 5 corp: badformat") is None

    def test_corp_size_double_dot_rejected(self):
        # libFuzzer's ScaleBytes() emits exactly one of: <int>b, <float>k, <float>Mb.
        # Inputs like '1..5' or '..k' are not valid libFuzzer output and must be
        # rejected so a corrupted/spoofed log line cannot silently parse as a Pulse.
        line = "#100\tpulse cov: 5 ft: 5 corp: 4/1..5Mb exec/s: 100 rss: 64Mb"
        assert parse_pulse_line(line) is None

    def test_corp_size_missing_unit_rejected(self):
        # Just digits with no b/k/Mb suffix is not a libFuzzer-emitted size.
        line = "#100\tpulse cov: 5 ft: 5 corp: 4/1234 exec/s: 100 rss: 64Mb"
        assert parse_pulse_line(line) is None

    def test_corp_size_unknown_unit_rejected(self):
        # libFuzzer never emits 'Gb', 'Tb', or trailing letters outside b/k/Mb.
        line = "#100\tpulse cov: 5 ft: 5 corp: 4/1.5Gb exec/s: 100 rss: 64Mb"
        assert parse_pulse_line(line) is None



class TestParseTargets:
    SAMPLE_CARGO_TOML = """\
[workspace]

[package]
name = "secretary-core-fuzz"

[[bin]]
name = "vault_toml"
path = "fuzz_targets/vault_toml.rs"
test = false

[[bin]]
name = "record"
path = "fuzz_targets/record.rs"
test = false
"""

    def test_extracts_two_targets(self):
        names = parse_targets(self.SAMPLE_CARGO_TOML)
        assert names == ["vault_toml", "record"]

    def test_empty_cargo_toml(self):
        assert parse_targets("[package]\nname = 'foo'\n") == []

    def test_six_targets_in_order(self):
        toml_text = "\n".join(
            f'[[bin]]\nname = "{n}"\npath = "fuzz_targets/{n}.rs"\n'
            for n in ["vault_toml", "record", "contact_card", "bundle_file", "manifest_file", "block_file"]
        )
        assert parse_targets(toml_text) == [
            "vault_toml", "record", "contact_card",
            "bundle_file", "manifest_file", "block_file",
        ]

    def test_malformed_toml_raises(self):
        with pytest.raises(Exception):  # tomllib.TOMLDecodeError
            parse_targets("[[bin\nname = 'unclosed")



class TestCheckPlateau:
    @staticmethod
    def _pulse(cov: int, corp: int, exec_count: int = 1000) -> Pulse:
        return Pulse(exec_count=exec_count, cov=cov, ft=cov * 2, corp=corp, exec_s=50000, rss=128)

    def test_empty_window_returns_false(self):
        assert check_plateau([], k=10) is False

    def test_window_shorter_than_k_returns_false(self):
        window = [self._pulse(100, 5) for _ in range(5)]
        assert check_plateau(window, k=10) is False

    def test_full_window_all_equal_returns_true(self):
        window = [self._pulse(100, 5) for _ in range(10)]
        assert check_plateau(window, k=10) is True

    def test_full_window_cov_changed_at_end_returns_false(self):
        window = [self._pulse(100, 5) for _ in range(9)] + [self._pulse(101, 5)]
        assert check_plateau(window, k=10) is False

    def test_full_window_corp_changed_in_middle_returns_false(self):
        window = (
            [self._pulse(100, 5) for _ in range(4)]
            + [self._pulse(100, 6)]
            + [self._pulse(100, 6) for _ in range(5)]
        )
        assert check_plateau(window, k=10) is False

    def test_window_longer_than_k_uses_last_k(self):
        # First entry has different cov; last K=5 are all equal
        window = [self._pulse(99, 5)] + [self._pulse(100, 5) for _ in range(5)]
        assert check_plateau(window, k=5) is True

    def test_k_one_always_true_with_one_pulse(self):
        # Trivial case: K=1 means "no growth in last 1 pulse" — always trivially true.
        window = [self._pulse(100, 5)]
        assert check_plateau(window, k=1) is True


from pathlib import Path


class TestFindNightlyToolchain:
    def test_returns_most_recent_nightly(self, tmp_path: Path):
        rustup_home = tmp_path / "rustup"
        toolchains = rustup_home / "toolchains"
        toolchains.mkdir(parents=True)
        (toolchains / "stable-aarch64-apple-darwin").mkdir()
        older = toolchains / "nightly-2026-04-28-aarch64-apple-darwin"
        newer = toolchains / "nightly-2026-04-29-aarch64-apple-darwin"
        older.mkdir()
        newer.mkdir()
        # Set newer's mtime explicitly to a later moment.
        import os, time
        os.utime(older, (time.time() - 100, time.time() - 100))
        os.utime(newer, (time.time(), time.time()))

        result = find_nightly_toolchain(rustup_home)
        assert result is not None
        assert result.name == "nightly-2026-04-29-aarch64-apple-darwin"

    def test_returns_none_when_no_nightly(self, tmp_path: Path):
        rustup_home = tmp_path / "rustup"
        (rustup_home / "toolchains" / "stable-x").mkdir(parents=True)
        assert find_nightly_toolchain(rustup_home) is None

    def test_returns_none_when_toolchains_dir_missing(self, tmp_path: Path):
        rustup_home = tmp_path / "rustup"
        rustup_home.mkdir()  # no toolchains subdir
        assert find_nightly_toolchain(rustup_home) is None

    def test_returns_none_when_rustup_home_missing(self, tmp_path: Path):
        rustup_home = tmp_path / "does-not-exist"
        assert find_nightly_toolchain(rustup_home) is None



class TestBuildSubprocessEnv:
    def test_prepends_nightly_bin_to_path(self):
        nightly_dir = Path("/Users/me/.rustup/toolchains/nightly-2026-04-29-x")
        base_env = {"PATH": "/usr/local/bin:/usr/bin", "HOME": "/Users/me"}
        env = build_subprocess_env(nightly_dir, base_env)
        assert env["PATH"].startswith("/Users/me/.rustup/toolchains/nightly-2026-04-29-x/bin:")
        assert env["PATH"].endswith(":/usr/local/bin:/usr/bin")
        assert env["HOME"] == "/Users/me"

    def test_preserves_other_env_vars(self):
        nightly_dir = Path("/n")
        base_env = {"PATH": "/usr/bin", "RUSTFLAGS": "-Dwarnings", "FOO": "bar"}
        env = build_subprocess_env(nightly_dir, base_env)
        assert env["RUSTFLAGS"] == "-Dwarnings"
        assert env["FOO"] == "bar"

    def test_handles_missing_path(self):
        nightly_dir = Path("/n")
        base_env: dict[str, str] = {}  # no PATH key
        env = build_subprocess_env(nightly_dir, base_env)
        assert env["PATH"] == "/n/bin"

    def test_does_not_mutate_input(self):
        nightly_dir = Path("/n")
        base_env = {"PATH": "/usr/bin"}
        original = dict(base_env)
        build_subprocess_env(nightly_dir, base_env)
        assert base_env == original



class TestParseRunsCap:
    def test_empty_returns_none(self):
        assert parse_runs_cap("") is None
        assert parse_runs_cap("   ") is None

    def test_plain_integer(self):
        assert parse_runs_cap("5000000") == 5_000_000

    def test_underscore_separated(self):
        assert parse_runs_cap("5_000_000") == 5_000_000
        assert parse_runs_cap("1_000") == 1_000

    def test_with_surrounding_whitespace(self):
        assert parse_runs_cap("  5000000  ") == 5_000_000

    def test_negative_raises(self):
        with pytest.raises(ValueError):
            parse_runs_cap("-1")

    def test_zero_raises(self):
        with pytest.raises(ValueError):
            parse_runs_cap("0")

    def test_non_numeric_raises(self):
        with pytest.raises(ValueError):
            parse_runs_cap("abc")
        with pytest.raises(ValueError):
            parse_runs_cap("1.5")



class TestRunState:
    def test_default_state(self):
        rs = RunState(target="vault_toml", sanitizer="asan")
        assert rs.status == Status.IDLE
        assert rs.runs_cap is None
        assert rs.crash_path is None
        assert len(rs.pulses) == 0
        assert len(rs.log_tail) == 0

    def test_pulses_bounded(self):
        rs = RunState(target="vault_toml", sanitizer="asan")
        for i in range(100):
            rs.pulses.append(Pulse(exec_count=i, cov=0, ft=0, corp=0, exec_s=0, rss=0))
        assert len(rs.pulses) == 64  # maxlen=64

    def test_log_tail_bounded(self):
        rs = RunState(target="vault_toml", sanitizer="asan")
        for i in range(50):
            rs.log_tail.append(f"line {i}")
        assert len(rs.log_tail) == 20  # maxlen=20



class TestStatusBadgeClass:
    """Each Status enum value maps to a Quasar text-color class. The mapping
    is exhaustive so a future variant added to Status without a matching
    class entry surfaces as a missing-key error rather than a silent fallback
    to default text colour."""

    def test_idle_is_grey(self):
        assert status_badge_class(Status.IDLE) == "text-grey-7"

    def test_running_is_positive(self):
        assert status_badge_class(Status.RUNNING) == "text-positive"

    def test_plateau_is_warning(self):
        assert status_badge_class(Status.PLATEAU) == "text-warning"

    def test_cap_reached_is_info(self):
        assert status_badge_class(Status.CAP_REACHED) == "text-info"

    def test_crashed_is_negative(self):
        assert status_badge_class(Status.CRASHED) == "text-negative"

    def test_stopped_is_grey(self):
        assert status_badge_class(Status.STOPPED) == "text-grey-7"

    def test_exhaustive_over_status_enum(self):
        # If a new Status variant lands without a matching class entry, this
        # test fails with the missing variant name in the assertion.
        for status in Status:
            cls = status_badge_class(status)
            assert cls.startswith("text-"), (
                f"{status.name} maps to {cls!r}, expected Quasar text-* class"
            )



class TestEffectiveSanitizerKey:
    """Regression: the radio offers an 'asan'/'ubsan'/'both' meta-option, but
    self.runs is only keyed by 'asan'/'ubsan'. Without remap, every per-card
    timer tick raised KeyError once the user picked 'both'."""

    def test_asan_passthrough(self):
        assert effective_sanitizer_key("asan", Status.IDLE) == "asan"
        assert effective_sanitizer_key("asan", Status.RUNNING) == "asan"

    def test_ubsan_passthrough(self):
        assert effective_sanitizer_key("ubsan", Status.IDLE) == "ubsan"
        assert effective_sanitizer_key("ubsan", Status.CRASHED) == "ubsan"

    def test_both_resolves_to_asan_when_ubsan_idle(self):
        # Before chain has reached UBSan (or chain abandoned because ASan
        # crashed/user-stopped), the live state lives on the ASan slot.
        assert effective_sanitizer_key("both", Status.IDLE) == "asan"

    def test_both_resolves_to_ubsan_once_started(self):
        # Once _chain_ubsan flips UBSan to RUNNING, that's the live state.
        for s in (Status.RUNNING, Status.PLATEAU, Status.CAP_REACHED,
                  Status.CRASHED, Status.STOPPED):
            assert effective_sanitizer_key("both", s) == "ubsan", s.name


def _svg_root(svg_text: str) -> ET.Element:
    """Parse an SVG string. Strips XML namespace prefix from the tag so the
    test assertions can use bare tag names like 'polyline' / 'circle' without
    juggling '{http://www.w3.org/2000/svg}polyline'."""
    root = ET.fromstring(svg_text)
    for el in root.iter():
        if "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


def _polyline_points(root: ET.Element) -> list[tuple[float, float]]:
    pl = root.find("polyline")
    assert pl is not None, "expected one <polyline>"
    return [
        (float(x), float(y))
        for token in pl.attrib["points"].split()
        for x, y in [token.split(",")]
    ]


class TestRenderSparklineSvg:
    """Inline SVG cov sparkline. Pure function: deterministic SVG string from a
    deque of cov values + width/height. No NiceGUI, no I/O — covers the visual
    'is cov still climbing?' question for the per-card live view."""

    W = 280
    H = 36

    def test_empty_returns_empty_svg(self):
        svg = render_sparkline_svg([], self.W, self.H)
        root = _svg_root(svg)
        assert root.find("polyline") is None
        assert root.find("circle") is None

    def test_single_value_renders_dot(self):
        svg = render_sparkline_svg([100], self.W, self.H)
        root = _svg_root(svg)
        circles = root.findall("circle")
        assert len(circles) == 1
        # Anchored to the right edge so the lone sample reads as "newest".
        cx = float(circles[0].attrib["cx"])
        assert cx > self.W - 5

    def test_two_growing_values_polyline_rises(self):
        # In SVG, y grows downward — a rising cov series produces *decreasing*
        # y values. Verifying the orientation guards against an accidental sign
        # flip in the y-mapping.
        svg = render_sparkline_svg([100, 200], self.W, self.H)
        pts = _polyline_points(_svg_root(svg))
        assert len(pts) == 2
        assert pts[0][1] > pts[1][1], (
            f"rising cov should produce decreasing SVG y; got {pts}"
        )

    def test_flat_values_render_centered_line(self):
        # All-equal series collapses pad math (range=0); the line is forced to
        # the vertical centre rather than dividing by zero.
        svg = render_sparkline_svg([100, 100, 100], self.W, self.H)
        pts = _polyline_points(_svg_root(svg))
        assert len(pts) == 3
        for _, y in pts:
            assert y == pytest.approx(self.H / 2, abs=0.5)

    def test_y_axis_padded_so_extremes_not_flush(self):
        # 10% padding on top and bottom: lowest data point is not at y=H-1,
        # highest is not at y=0. Without padding a campaign that's plateauing
        # would render a polyline glued to the canvas edge — visually
        # indistinguishable from a flat-line render.
        svg = render_sparkline_svg([100, 200], self.W, self.H)
        pts = _polyline_points(_svg_root(svg))
        ys = [y for _, y in pts]
        assert min(ys) > 1, f"top point should not be flush against y=0: {ys}"
        assert max(ys) < self.H - 2, (
            f"bottom point should not be flush against y=H-1: {ys}"
        )

    def test_x_axis_evenly_spaced(self):
        # Uniform x spacing reads cleaner than data-driven spacing for libFuzzer
        # pulses (whose exec_count grows in powers of 2). The x axis is "pulse
        # slot index", not exec count.
        svg = render_sparkline_svg([10, 20, 30, 40, 50], self.W, self.H)
        pts = _polyline_points(_svg_root(svg))
        xs = [x for x, _ in pts]
        gaps = [xs[i + 1] - xs[i] for i in range(len(xs) - 1)]
        for g in gaps:
            assert g == pytest.approx(gaps[0], abs=0.5), f"uneven x spacing: {gaps}"


def _classify_dot(circle: ET.Element) -> str:
    """Map a dot-strip <circle> to its semantic state by inspecting style.
    Decoupled from exact color hex strings so a future palette tweak doesn't
    cascade across every test assertion."""
    fill = circle.attrib.get("fill", "")
    if fill == "none":
        return "outline"
    if "16a34a" in fill.lower():
        return "growth"
    if "9ca3af" in fill.lower():
        return "flat"
    raise AssertionError(f"unexpected dot styling: {circle.attrib}")


def _strip_dots(svg_text: str) -> list[str]:
    root = _svg_root(svg_text)
    return [_classify_dot(c) for c in root.findall("circle")]


def _make_pulse(exec_count: int, cov: int, corp: int) -> "Pulse":
    """Pulse with sane non-plateau-relevant fields. ft and exec_s and rss
    don't drive plateau detection — set to placeholders so the tests stay
    focused on the cov/corp dimensions that the dot strip cares about."""
    return Pulse(
        exec_count=exec_count, cov=cov, ft=cov, corp=corp, exec_s=1000, rss=64
    )


class TestRenderPlateauStripSvg:
    """Plateau dot strip. K-1 transition dots, newest right. Strip-all-grey
    is exactly the plateau condition (last K pulses share same cov AND corp).
    Empty/outline dots fill the leftmost slots when fewer than K pulses
    exist yet, so the strip still occupies its full width."""

    K = 10
    W = 280

    def test_empty_pulses_all_outline(self):
        # No pulses yet → strip occupies its slot but communicates "nothing
        # to compare". All K-1 dots render as outlines.
        dots = _strip_dots(render_plateau_strip_svg([], self.K, frozen=False))
        assert dots == ["outline"] * (self.K - 1)

    def test_partial_history_remaining_outline(self):
        # 3 pulses, K=10 → only the rightmost 2 transitions are paintable
        # (pulses[-3]→[-2] and pulses[-2]→[-1]); the 7 leftward slots stay
        # outline-only since their pulse pair doesn't exist yet.
        pulses = [
            _make_pulse(1, 10, 1),
            _make_pulse(2, 20, 2),
            _make_pulse(4, 30, 3),
        ]
        dots = _strip_dots(render_plateau_strip_svg(pulses, self.K, frozen=False))
        assert dots == ["outline"] * 7 + ["growth", "growth"]

    def test_full_growth_window_all_green(self):
        # 10 strictly-increasing pulses → 9 green dots. This is the
        # "campaign is healthy" baseline: nothing flat, plateau distant.
        pulses = [_make_pulse(2 ** i, 10 + i, 1 + i) for i in range(10)]
        dots = _strip_dots(render_plateau_strip_svg(pulses, self.K, frozen=False))
        assert dots == ["growth"] * 9

    def test_full_plateau_window_all_grey(self):
        # 10 pulses with constant cov AND corp → 9 grey dots. This is
        # *exactly* the plateau condition the detector uses; the strip
        # going all-grey must coincide with `check_plateau` returning True.
        pulses = [_make_pulse(2 ** i, 100, 5) for i in range(10)]
        dots = _strip_dots(render_plateau_strip_svg(pulses, self.K, frozen=False))
        assert dots == ["flat"] * 9

    def test_one_increase_at_left_boundary(self):
        # Leftmost transition grew, rest flat → leftmost dot green, 8 grey.
        # Verifies dot ordering (leftmost = oldest transition, rightmost =
        # newest) is the user-intuitive "history flows left to right".
        pulses = [_make_pulse(1, 100, 5)]
        pulses.append(_make_pulse(2, 110, 6))  # growth here
        for i in range(2, 10):
            pulses.append(_make_pulse(2 ** i, 110, 6))  # all flat after
        dots = _strip_dots(render_plateau_strip_svg(pulses, self.K, frozen=False))
        assert dots == ["growth"] + ["flat"] * 8

    def test_corp_growth_alone_counts_as_growth(self):
        # Plateau definition is "cov AND corp both flat", so corp growing
        # alone breaks the plateau and should show as growth — not flat.
        # Without this rule, a corpus minimization step could mask an
        # otherwise-active campaign.
        pulses = [_make_pulse(2 ** i, 100, 5 + i) for i in range(10)]
        dots = _strip_dots(render_plateau_strip_svg(pulses, self.K, frozen=False))
        assert dots == ["growth"] * 9

    @pytest.mark.parametrize("k", [2, 5, 10, 20])
    def test_dot_count_equals_k_minus_one(self, k):
        dots = _strip_dots(render_plateau_strip_svg([], k, frozen=False))
        assert len(dots) == k - 1


class TestChartIntegrationWithMonitorApp:
    """Smoke test that the same code path executed by `update_card` runs
    end-to-end against a live `MonitorApp` instance — including the
    'both' meta-option remap that previously KeyError'd. Doesn't render
    NiceGUI elements; verifies the data plumbing (effective_sanitizer_key
    → self.runs lookup → render_*_svg) works on a populated RunState."""

    def test_both_radio_through_chart_renderers_no_keyerror(self):
        from monitor import MonitorApp

        app = MonitorApp(["t1"])
        rs = app.runs[("t1", "asan")]
        for i in range(5):
            rs.pulses.append(_make_pulse(2 ** i, 100 + i, 1 + i))

        # Mirror update_card: resolve "both" → effective key, look up rs,
        # render. If the key remap regressed, this raises KeyError.
        key = effective_sanitizer_key("both", app.runs[("t1", "ubsan")].status)
        live = app.runs[("t1", key)]
        cov_series = [p.cov for p in live.pulses]

        sparkline_svg = render_sparkline_svg(cov_series, 280, 36)
        strip_svg = render_plateau_strip_svg(
            list(live.pulses), app.plateau_k, frozen=False
        )

        # Sanity-check both outputs parse and contain content matching the
        # populated state (one polyline, partial-fill dot strip with 4
        # right-aligned growth dots inside otherwise-outline slots).
        assert _svg_root(sparkline_svg).find("polyline") is not None
        dots = _strip_dots(strip_svg)
        assert dots[-4:] == ["growth"] * 4
        assert all(d == "outline" for d in dots[:-4])


class TestFormatPulseReadout:
    """`pulses[-1]` rendered as a single readable line for the card body.
    `None` (no pulses yet) renders as an em-dash so the user can tell
    'no telemetry yet' apart from 'telemetry says zero'."""

    def test_none_renders_em_dash(self):
        # Distinguishes idle / pre-INITED from "telemetry says zero".
        assert format_pulse_readout(None) == "—"

    def test_typical_pulse(self):
        p = Pulse(exec_count=1048576, cov=1247, ft=2891, corp=142, exec_s=58000, rss=124)
        assert (
            format_pulse_readout(p)
            == "cov 1247 / ft 2891 / corp 142 / 58000 exec/s / 124 MB"
        )

    def test_zero_pulse_renders_zeros_not_dash(self):
        # A real Pulse with all-zero counters (early INITED before first
        # iteration) must render explicit zeros, not the em-dash. The em-dash
        # is reserved for 'no Pulse at all'.
        p = Pulse(exec_count=0, cov=0, ft=0, corp=0, exec_s=0, rss=0)
        assert format_pulse_readout(p) == "cov 0 / ft 0 / corp 0 / 0 exec/s / 0 MB"



class TestFormatElapsed:
    """Elapsed-since-spawn rendered in `mm:ss` for short runs and
    `h:mm:ss` once the campaign crosses an hour."""

    def test_zero(self):
        assert format_elapsed(0) == "00:00"

    def test_under_a_minute(self):
        assert format_elapsed(7) == "00:07"

    def test_full_minute(self):
        assert format_elapsed(60) == "01:00"

    def test_typical_minutes_seconds(self):
        assert format_elapsed(65) == "01:05"
        assert format_elapsed(305) == "05:05"

    def test_just_under_an_hour(self):
        # Stays in mm:ss until exactly 1 hour.
        assert format_elapsed(3599) == "59:59"

    def test_one_hour_switches_to_h_mm_ss(self):
        assert format_elapsed(3600) == "1:00:00"

    def test_hours_minutes_seconds(self):
        assert format_elapsed(3661) == "1:01:01"

    def test_fractional_seconds_truncated(self):
        # Sub-second time.monotonic() differences shouldn't show as 00:00.5;
        # truncate to whole seconds.
        assert format_elapsed(7.9) == "00:07"

    def test_negative_clamped_to_zero(self):
        # Defensive against clock skew between time.monotonic() reads.
        assert format_elapsed(-1) == "00:00"


class TestFormatHumanCount:
    """SI-suffix counter formatting (decimal: 1k = 1,000, 1M = 1,000,000)
    used for both exec_count and runs_cap. Trailing `.0` is stripped so
    round numbers read as `1k` not `1.0k`."""

    def test_below_thousand(self):
        assert format_human_count(0) == "0"
        assert format_human_count(999) == "999"

    def test_round_thousand(self):
        assert format_human_count(1_000) == "1k"

    def test_kilo_with_decimal(self):
        assert format_human_count(1_234) == "1.2k"

    def test_kilo_double_digit(self):
        assert format_human_count(12_345) == "12.3k"

    def test_kilo_triple_digit(self):
        # Truncated, not rounded: 123_456 / 1000 = 123.456 -> "123.4k".
        # Was "123.5k" pre-truncation switch; see docstring on
        # `_trim_decimal` for why truncation matches the magnitude
        # branch's intent (caller already chose kilo, the decimal must
        # not push into mega).
        assert format_human_count(123_456) == "123.4k"

    def test_round_million(self):
        assert format_human_count(1_000_000) == "1M"
        assert format_human_count(5_000_000) == "5M"

    def test_million_with_decimal(self):
        assert format_human_count(1_200_000) == "1.2M"

    def test_giga(self):
        assert format_human_count(1_234_567_890) == "1.2G"

    # ---- Boundary behaviour, pinned per review ----

    def test_one_above_thousand_collapses_to_round(self):
        # 1001 / 1000 = 1.001, truncated to 1.0, trailing .0 stripped.
        # Documents the small precision loss right above each magnitude.
        assert format_human_count(1_001) == "1k"

    def test_just_below_million_stays_in_kilo_magnitude(self):
        # Regression pin: `:.1f` would round 999.999 -> "1000.0", which
        # made the function render `999_999` as "1000k". Truncation
        # keeps the magnitude consistent with the branch the caller
        # took: kilo branch -> kilo string.
        assert format_human_count(999_999) == "999.9k"

    def test_one_above_million_collapses_to_round(self):
        # Mirror of the kilo case, in mega.
        assert format_human_count(1_000_001) == "1M"

    def test_just_below_giga_stays_in_mega_magnitude(self):
        # Mirror of the 999_999 -> "999.9k" pin, one magnitude up.
        assert format_human_count(999_999_999) == "999.9M"

    def test_one_above_giga_collapses_to_round(self):
        assert format_human_count(1_000_000_001) == "1G"


class TestFormatRunsProgress:
    """`exec_count / runs_cap` (e.g. '1.2M / 5M') when capped, just
    `exec_count` when open-ended."""

    def test_open_ended(self):
        assert format_runs_progress(1_234, None) == "1.2k"

    def test_open_ended_zero(self):
        assert format_runs_progress(0, None) == "0"

    def test_capped(self):
        assert format_runs_progress(1_200_000, 5_000_000) == "1.2M / 5M"

    def test_capped_at_zero(self):
        assert format_runs_progress(0, 1_000_000) == "0 / 1M"



class TestCategorizeArtifact:
    """libFuzzer artifact filenames carry their kind as the prefix; the
    rest of the name is a SHA-1 of the input. `.gitkeep` is the
    placeholder file each empty regression dir ships with."""

    def test_oom(self):
        assert categorize_artifact("oom-031e9f63c25e22eef.bin") == "oom"

    def test_slow_unit(self):
        assert categorize_artifact("slow-unit-bca8ee9d63ee08277.bin") == "slow-unit"

    def test_crash(self):
        assert categorize_artifact("crash-abcd1234.bin") == "crash"

    def test_unknown_returns_none(self):
        assert categorize_artifact("not-an-artifact.bin") is None

    def test_gitkeep_returns_none(self):
        assert categorize_artifact(".gitkeep") is None

    def test_empty_returns_none(self):
        assert categorize_artifact("") is None


class TestAggregateArtifactCounts:
    """Folds a sequence of filenames into per-kind counts; ignores names
    that don't categorise."""

    def test_empty(self):
        assert aggregate_artifact_counts([]) == {}

    def test_mixed(self):
        names = [
            "oom-1.bin",
            "oom-2.bin",
            "slow-unit-1.bin",
            "crash-1.bin",
            ".gitkeep",
            "junk.txt",
        ]
        assert aggregate_artifact_counts(names) == {
            "oom": 2,
            "slow-unit": 1,
            "crash": 1,
        }

    def test_only_unrecognised(self):
        assert aggregate_artifact_counts([".gitkeep", "junk", "README.md"]) == {}


class TestFormatFindingsSummary:
    """Single-line tally rendered above the card grid. Order is stable
    (oom, slow-unit, crash) so the line doesn't shuffle as findings
    accumulate. Singular vs plural is per-kind."""

    def test_none(self):
        assert (
            format_findings_summary({}, target_count=4)
            == "Findings: none across 4 targets"
        )

    def test_one_oom_singular(self):
        assert (
            format_findings_summary({"oom": 1}, target_count=4)
            == "Findings: 1 OOM across 4 targets"
        )

    def test_two_oom_plural(self):
        assert (
            format_findings_summary({"oom": 2}, target_count=4)
            == "Findings: 2 OOMs across 4 targets"
        )

    def test_doc_example(self):
        # The exact format the spec calls out.
        counts = {"oom": 2, "slow-unit": 2}
        assert (
            format_findings_summary(counts, target_count=4)
            == "Findings: 2 OOMs, 2 slow-units across 4 targets"
        )

    def test_stable_kind_order(self):
        # All three kinds present at once: oom -> slow-unit -> crash.
        counts = {"crash": 1, "slow-unit": 2, "oom": 3}
        assert (
            format_findings_summary(counts, target_count=6)
            == "Findings: 3 OOMs, 2 slow-units, 1 crash across 6 targets"
        )

    def test_three_crashes_pluralised(self):
        assert (
            format_findings_summary({"crash": 3}, target_count=4)
            == "Findings: 3 crashes across 4 targets"
        )

    def test_one_target_singular(self):
        assert (
            format_findings_summary({}, target_count=1)
            == "Findings: none across 1 target"
        )



class TestFormatCardElapsed:
    """Per-card `elapsed: ...` label. Three regimes: never started,
    running (live tick), terminal (frozen at the captured stop time).
    The frozen value is captured the moment the subprocess actually
    exits — review caught that the previous "skip-update on terminal
    status" approach left the displayed value ~1 s late."""

    def test_never_started_renders_em_dash(self):
        # started_at == 0.0 means the card has never been started.
        assert (
            format_card_elapsed(
                started_at=0.0, stopped_at=0.0, is_running=False, now=100.0
            )
            == "elapsed: —"
        )

    def test_running_uses_live_now(self):
        # 7-second tick: now - started_at = 7.
        assert (
            format_card_elapsed(
                started_at=100.0, stopped_at=0.0, is_running=True, now=107.0
            )
            == "elapsed: 00:07"
        )

    def test_terminal_uses_frozen_stopped_at(self):
        # Subprocess exited at started_at + 65; later ticks at much
        # higher `now` must NOT keep advancing the elapsed value.
        assert (
            format_card_elapsed(
                started_at=100.0, stopped_at=165.0, is_running=False, now=999.0
            )
            == "elapsed: 01:05"
        )

    def test_terminal_frozen_value_stable_across_repeated_ticks(self):
        # Pin the regression directly: two ticks at different `now`
        # values both produce the same elapsed string in the frozen
        # regime. This is what "skip-update" used to fake; we now
        # produce the same answer deterministically.
        first = format_card_elapsed(
            started_at=10.0, stopped_at=70.0, is_running=False, now=100.0
        )
        later = format_card_elapsed(
            started_at=10.0, stopped_at=70.0, is_running=False, now=10_000.0
        )
        assert first == later == "elapsed: 01:00"

    def test_terminal_without_stopped_at_falls_back_to_now(self):
        # Defensive: terminal status with stopped_at == 0.0 shouldn't
        # arise from the current call sites, but the helper should not
        # crash. Falls back to `now - started_at`.
        assert (
            format_card_elapsed(
                started_at=100.0, stopped_at=0.0, is_running=False, now=130.0
            )
            == "elapsed: 00:30"
        )
