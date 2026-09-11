import pytest

from mutation_harness.spec import SpecError, parse_spec
from mutation_harness.types import Expect, Lang, PythonProbe, RustProbe

# A STRING-valued expression, deliberately: `equals` is compared against the
# `repr()` of what `expr` evaluates to, so the earlier `x = 1 -> x = 2` with
# `equals = "2"` was a fixture that could never be live — a reader copying it
# as a template got `NOT_LIVE` on every row (PR #652 review).
MINIMAL_PY = """
[[mutation]]
id = "M1"
lang = "python"
path = "a.py"
old = 'x = "one"'
new = 'x = "two"'
gate = "true"
expect = "red"
probe = { module = "a", expr = "x", equals = "two", syspath = "." }
"""


@pytest.fixture
def repo(tmp_path):
    (tmp_path / "a.py").write_text('x = "one"\n')
    return tmp_path


def test_parses_a_minimal_python_mutation(repo):
    specs = parse_spec(MINIMAL_PY, repo)
    assert len(specs) == 1
    s = specs[0]
    assert s.id == "M1"
    assert s.lang is Lang.PYTHON
    assert s.expect is Expect.RED
    assert isinstance(s.probe, PythonProbe)
    assert s.probe.equals == "two"
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


def test_unknown_top_level_key_is_an_error(repo):
    bad = MINIMAL_PY + '\nnote_typo = "oops"\n'
    with pytest.raises(SpecError, match="unknown key"):
        parse_spec(bad, repo)


def test_unknown_document_level_key_is_an_error(repo):
    """`parse_spec` read only `doc["mutation"]`, so a `timeout` written at
    the document level instead of inside the block was inert — the exact
    "silently degrades a check" shape the module forbids (PR #652 review)."""
    bad = "timeout = 5\n" + MINIMAL_PY
    with pytest.raises(SpecError, match="unknown top-level key"):
        parse_spec(bad, repo)


def test_unknown_probe_key_is_an_error(repo):
    bad = MINIMAL_PY.replace('syspath = "."', 'syspath = ".", typo = 1')
    with pytest.raises(SpecError, match="unknown probe key"):
        parse_spec(bad, repo)


def test_missing_required_key_is_an_error(tmp_path):
    bad = MINIMAL_PY.replace('gate = "true"\n', "")
    with pytest.raises(SpecError, match="missing required key"):
        parse_spec(bad, tmp_path)


def test_expect_must_be_red_or_green(repo):
    bad = MINIMAL_PY.replace('expect = "red"', 'expect = "maybe"')
    with pytest.raises(SpecError, match="expect"):
        parse_spec(bad, repo)


def test_path_escaping_the_repo_root_is_an_error(tmp_path):
    bad = MINIMAL_PY.replace('path = "a.py"', 'path = "../outside.py"')
    with pytest.raises(SpecError, match="outside the repository"):
        parse_spec(bad, tmp_path)


def test_a_path_that_is_not_an_existing_file_is_an_error(tmp_path):
    """A typo'd path used to pass containment, burn the full baseline gate,
    and then traceback out of `journal.record` (PR #652 review)."""
    with pytest.raises(SpecError, match="not an existing file"):
        parse_spec(MINIMAL_PY, tmp_path)
    (tmp_path / "a.py").mkdir()
    with pytest.raises(SpecError, match="not an existing file"):
        parse_spec(MINIMAL_PY, tmp_path)


def test_a_syspath_that_is_not_an_existing_directory_is_an_error(repo):
    bad = MINIMAL_PY.replace('syspath = "."', 'syspath = "lib/nope"')
    with pytest.raises(SpecError, match="syspath"):
        parse_spec(bad, repo)
    escaped = MINIMAL_PY.replace('syspath = "."', 'syspath = "../.."')
    with pytest.raises(SpecError, match="outside the repository"):
        parse_spec(escaped, repo)


def test_duplicate_ids_are_an_error(repo):
    with pytest.raises(SpecError, match="duplicate id"):
        parse_spec(MINIMAL_PY + MINIMAL_PY, repo)


def test_a_python_mutation_may_not_carry_a_rust_probe(repo):
    bad = MINIMAL_PY.replace(
        'probe = { module = "a", expr = "x", equals = "two", syspath = "." }',
        'probe = { package = "demo" }',
    )
    with pytest.raises(SpecError, match="unknown probe key"):
        parse_spec(bad, repo)


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
def test_a_wrong_typed_field_is_a_spec_error(repo, field, bad_toml):
    original = next(line for line in MINIMAL_PY.splitlines() if line.startswith(f"{field} ="))
    bad = MINIMAL_PY.replace(original, bad_toml)
    assert bad != MINIMAL_PY, f"failed to substitute {field}"

    with pytest.raises(SpecError):
        parse_spec(bad, repo)


def test_a_wrong_typed_note_is_a_spec_error(repo):
    with pytest.raises(SpecError, match="note must be a string"):
        parse_spec(MINIMAL_PY + "note = 5\n", repo)


def test_a_wrong_typed_probe_field_is_a_spec_error(repo):
    """The probe's own fields had the same `str()` coercion — a non-string
    `module` would have been coerced and then failed the dotted-identifier
    check at probe time, a whole pipeline later."""
    bad = MINIMAL_PY.replace('module = "a"', "module = 5")
    with pytest.raises(SpecError, match="module must be a string"):
        parse_spec(bad, repo)


def test_a_coerced_gate_never_reaches_the_spec(repo):
    """The consequence, spelled out: before this fix `gate = { a = 1 }`
    produced the literal shell command `{'a': 1}`, i.e. a spec typo became an
    executed command line."""
    bad = MINIMAL_PY.replace('gate = "true"', "gate = { a = 1 }")
    with pytest.raises(SpecError, match="gate must be a string"):
        parse_spec(bad, repo)


# --- PR #652 review: the two validators that had no test at all -------------


@pytest.mark.parametrize(
    "value", ["true", "0", '"5"', "-1", "1.5"], ids=["bool", "zero", "string", "negative", "float"]
)
def test_timeout_must_be_a_positive_integer(repo, value):
    """`bool` is a subclass of `int`, so `timeout = true` would otherwise
    parse as `timeout = 1` — the one line a "simplification" deletes."""
    with pytest.raises(SpecError, match="timeout must be a positive integer"):
        parse_spec(MINIMAL_PY + f"timeout = {value}\n", repo)


def test_timeout_is_parsed_when_valid(repo):
    (s,) = parse_spec(MINIMAL_PY + "timeout = 42\n", repo)
    assert s.timeout == 42


@pytest.mark.parametrize("value", ['"t"', "[1]", "[\"a\", 2]"], ids=["string", "int-list", "mixed"])
def test_expect_red_must_be_a_list_of_strings(repo, value):
    with pytest.raises(SpecError, match="expect_red must be a list of strings"):
        parse_spec(MINIMAL_PY + f"expect_red = {value}\n", repo)
