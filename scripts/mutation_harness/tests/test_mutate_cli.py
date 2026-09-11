"""`mutate.main`'s refusal surface. Final whole-branch review, Finding 5.

`SpecError` and a bad spec PATH already exited 2 with a `mutate:` line. A
journal that could not be OPENED did not: `Journal(journal_dir)` is
constructed outside every handler, so a `CorruptJournal` — the one error whose
whole value is telling a reader that backup blobs remain on disk and a human
must decide — reached the user as a traceback instead.
"""

import io
from contextlib import redirect_stderr, redirect_stdout

import pytest

import mutate


def _run(argv) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = mutate.main(argv)
    return code, out.getvalue(), err.getvalue()


def _corrupt_journal_dir(tmp_path, body: str = "{not valid json"):
    journal_dir = tmp_path / "jdir"
    journal_dir.mkdir()
    (journal_dir / "mutation-journal.json").write_text(body)
    return journal_dir


@pytest.mark.parametrize(
    "body",
    ["{not valid json", '["a JSON list, not an object"]', '{"entries": 5}'],
    ids=["unparseable", "top-list", "entries-int"],
)
def test_a_corrupt_journal_exits_2_with_a_mutate_message(tmp_path, body):
    journal_dir = _corrupt_journal_dir(tmp_path, body)
    spec_path = tmp_path / "spec.toml"
    spec_path.write_text("")

    code, _, err = _run([str(spec_path), "--journal-dir", str(journal_dir)])

    assert code == 2
    assert err.startswith("mutate: ")
    assert "do not proceed without manual review" in err


def test_a_corrupt_journal_exits_2_on_drain_too(tmp_path):
    """`--drain` is the documented remedy for a dirty journal, so it is the
    path a reader is MOST likely to reach with a damaged index in hand."""
    journal_dir = _corrupt_journal_dir(tmp_path)

    code, _, err = _run(["--drain", "--journal-dir", str(journal_dir)])

    assert code == 2
    assert err.startswith("mutate: ")


def test_a_missing_spec_file_still_exits_2(tmp_path):
    """The pre-existing OSError path, kept pinned alongside the new one."""
    code, _, err = _run([str(tmp_path / "nope.toml"), "--journal-dir", str(tmp_path / "j")])

    assert code == 2
    assert err.startswith("mutate: ")


def test_a_wrong_typed_spec_field_exits_2_rather_than_tracebacking(tmp_path):
    """Finding 4's user-visible half: `expect = ["red"]` used to raise an
    untyped `TypeError: unhashable type: 'list'` out of `parse_spec`, which
    `main`'s `except (SpecError, OSError)` does not catch."""
    spec_path = tmp_path / "spec.toml"
    spec_path.write_text(
        "[[mutation]]\n"
        'id = "M1"\n'
        'lang = "python"\n'
        'path = "a.py"\n'
        'old = "x = 1"\n'
        'new = "x = 2"\n'
        'expect = ["red"]\n'
        'gate = "true"\n'
        'probe = { module = "a", expr = "x", equals = "2", syspath = "." }\n'
    )

    code, _, err = _run([str(spec_path), "--journal-dir", str(tmp_path / "j")])

    assert code == 2
    assert err.startswith("mutate: ")
    assert "expect must be a string" in err
