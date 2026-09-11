import pytest

from mutation_harness.spec import SpecError, parse_spec
from mutation_harness.types import Lang, PythonProbe, RustProbe

MINIMAL_PY = """
[[mutation]]
id = "M1"
lang = "python"
path = "a.py"
old = "x = 1"
new = "x = 2"
gate = "true"
expect = "red"
probe = { module = "a", expr = "x", equals = "2", syspath = "." }
"""


def test_parses_a_minimal_python_mutation(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    specs = parse_spec(MINIMAL_PY, tmp_path)
    assert len(specs) == 1
    s = specs[0]
    assert s.id == "M1"
    assert s.lang is Lang.PYTHON
    assert isinstance(s.probe, PythonProbe)
    assert s.probe.equals == "2"
    assert s.expect_red == ()


def test_parses_a_rust_mutation(tmp_path):
    (tmp_path / "a.rs").write_text("fn f() {}\n")
    text = """
[[mutation]]
id = "R1"
lang = "rust"
path = "a.rs"
old = "fn f"
new = "fn g"
gate = "true"
expect = "red"
expect_red = ["some_test"]
probe = { package = "demo" }
"""
    (s,) = parse_spec(text, tmp_path)
    assert s.lang is Lang.RUST
    assert isinstance(s.probe, RustProbe)
    assert s.probe.package == "demo"
    assert s.expect_red == ("some_test",)


def test_unknown_top_level_key_is_an_error(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    bad = MINIMAL_PY + '\nnote_typo = "oops"\n'
    with pytest.raises(SpecError, match="unknown key"):
        parse_spec(bad, tmp_path)


def test_unknown_probe_key_is_an_error(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    bad = MINIMAL_PY.replace('syspath = "."', 'syspath = ".", typo = 1')
    with pytest.raises(SpecError, match="unknown probe key"):
        parse_spec(bad, tmp_path)


def test_missing_required_key_is_an_error(tmp_path):
    bad = MINIMAL_PY.replace('gate = "true"\n', "")
    with pytest.raises(SpecError, match="missing required key"):
        parse_spec(bad, tmp_path)


def test_expect_must_be_red_or_green(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    bad = MINIMAL_PY.replace('expect = "red"', 'expect = "maybe"')
    with pytest.raises(SpecError, match="expect"):
        parse_spec(bad, tmp_path)


def test_path_escaping_the_repo_root_is_an_error(tmp_path):
    bad = MINIMAL_PY.replace('path = "a.py"', 'path = "../outside.py"')
    with pytest.raises(SpecError, match="outside the repository"):
        parse_spec(bad, tmp_path)


def test_duplicate_ids_are_an_error(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    with pytest.raises(SpecError, match="duplicate id"):
        parse_spec(MINIMAL_PY + MINIMAL_PY, tmp_path)


def test_a_python_mutation_may_not_carry_a_rust_probe(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    bad = MINIMAL_PY.replace(
        'probe = { module = "a", expr = "x", equals = "2", syspath = "." }',
        'probe = { package = "demo" }',
    )
    with pytest.raises(SpecError, match="unknown probe key"):
        parse_spec(bad, tmp_path)


def test_empty_spec_is_an_error(tmp_path):
    with pytest.raises(SpecError, match=r"no \[\[mutation\]\] blocks"):
        parse_spec("", tmp_path)


def test_a_single_table_instead_of_an_array_is_rejected(tmp_path):
    """`[mutation]` is a table; the format is an array of tables."""
    with pytest.raises(SpecError, match="array of tables"):
        parse_spec('[mutation]\nid = "M1"\n', tmp_path)


def test_a_non_table_array_element_is_rejected(tmp_path):
    """`mutation = [1, 2]` must be a SpecError, not a TypeError."""
    with pytest.raises(SpecError, match="must be a table"):
        parse_spec("mutation = [1, 2]\n", tmp_path)


def test_a_non_string_path_is_rejected(tmp_path):
    """A wrong-typed field must not reach the path arithmetic."""
    bad = MINIMAL_PY.replace('path = "a.py"', "path = 5")
    with pytest.raises(SpecError, match="path must be a string"):
        parse_spec(bad, tmp_path)
