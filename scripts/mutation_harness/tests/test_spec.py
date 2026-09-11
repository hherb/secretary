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


# --- Final whole-branch review, Findings 4/5: wrong-shaped input -----------
#
# `str()` coercion is not validation. Two of these used to raise an UNTYPED
# `TypeError: unhashable type` (never reaching `mutate.main`'s SpecError
# handler, so never an exit-2 `mutate:` line); the rest coerced silently into
# a plausible-looking value that was then EXECUTED as a shell command or
# spliced into a source file.


@pytest.mark.parametrize(
    "field, bad_toml",
    [
        ("expect", 'expect = ["red"]'),
        ("lang", "lang = { a = 1 }"),
        ("gate", "gate = { a = 1 }"),
        ("new", "new = [1, 2]"),
        ("old", "old = 7"),
        ("id", "id = 1"),
    ],
    ids=["expect-list", "lang-table", "gate-table", "new-array", "old-int", "id-int"],
)
def test_a_wrong_typed_field_is_a_spec_error(tmp_path, field, bad_toml):
    (tmp_path / "a.py").write_text("x = 1\n")
    original = next(line for line in MINIMAL_PY.splitlines() if line.startswith(f"{field} ="))
    bad = MINIMAL_PY.replace(original, bad_toml)
    assert bad != MINIMAL_PY, f"failed to substitute {field}"

    with pytest.raises(SpecError):
        parse_spec(bad, tmp_path)


def test_a_wrong_typed_note_is_a_spec_error(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    with pytest.raises(SpecError, match="note must be a string"):
        parse_spec(MINIMAL_PY + "note = 5\n", tmp_path)


def test_a_wrong_typed_probe_field_is_a_spec_error(tmp_path):
    """The probe's own fields had the same `str()` coercion — a non-string
    `module` would have been coerced and then failed the dotted-identifier
    check at probe time, a whole pipeline later."""
    (tmp_path / "a.py").write_text("x = 1\n")
    bad = MINIMAL_PY.replace('module = "a"', "module = 5")
    with pytest.raises(SpecError, match="module must be a string"):
        parse_spec(bad, tmp_path)


def test_a_coerced_gate_never_reaches_the_spec(tmp_path):
    """The consequence, spelled out: before this fix `gate = { a = 1 }`
    produced the literal shell command `{'a': 1}`, i.e. a spec typo became an
    executed command line."""
    (tmp_path / "a.py").write_text("x = 1\n")
    bad = MINIMAL_PY.replace('gate = "true"', "gate = { a = 1 }")
    with pytest.raises(SpecError, match="gate must be a string"):
        parse_spec(bad, tmp_path)
