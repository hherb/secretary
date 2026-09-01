"""Strict clean-room decode/encode ROUND-TRIP pairs behind `--diff-replay`.

Each `py_decode_<target>` / `py_encode_<target>` pair mirrors the Rust side's
acceptance set: the replay harness requires Rust and Python to agree on
ACCEPT vs REJECT, and on the re-encoded bytes when both accept.

The inspection-only parsers used by the golden-vault verification path live in
`conformance_lib.wire` instead.
"""
