"""Unit tests for `monitor.py` pure functions.

Run from the repo root:
    uv run --with pytest pytest core/fuzz/test_monitor.py -v
"""

from __future__ import annotations

# Imports populate as functions are added in later tasks.

import pytest

from monitor import Pulse, parse_pulse_line


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


from monitor import parse_targets


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


from monitor import check_plateau


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

from monitor import find_nightly_toolchain


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


from monitor import build_subprocess_env


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


from monitor import parse_runs_cap


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


from monitor import RunState, Status


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


from monitor import status_badge_class


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


from monitor import format_pulse_readout


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
