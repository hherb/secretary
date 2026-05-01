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
