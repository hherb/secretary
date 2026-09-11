"""`mutate.main`'s refusal surface and its exit-code contract.

Final whole-branch review, Finding 5: `SpecError` and a bad spec PATH already
exited 2 with a `mutate:` line. A journal that could not be OPENED did not:
`Journal(journal_dir)` is constructed outside every handler, so a
`CorruptJournal` — the one error whose whole value is telling a reader that
backup blobs remain on disk and a human must decide — reached the user as a
traceback instead.

PR #652 review: every exception other than `RestoreFailed` was a traceback
with exit 1 — the code documented for "a rendered table with an unsuccessful
row" — with every row already measured dropped. Exit 4 now names a harness
error, the partial table is rendered, and the tree is restored.
"""

import io
from contextlib import redirect_stderr, redirect_stdout

import pytest

import mutate
from mutation_harness.runner import RunAborted


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


def _spec_text(**overrides) -> str:
    fields = dict(
        id="M1", lang="python", path="m.py", old='"real"', new='"mutated"',
        gate="true", expect="green",
    )
    fields.update(overrides)
    lines = [f'{k} = {v!r}' if k not in ("old", "new") else f"{k} = '{v}'" for k, v in fields.items()]
    return (
        "[[mutation]]\n" + "\n".join(lines) + "\n"
        'probe = { module = "m", expr = "TOKEN", equals = "mutated", syspath = "." }\n'
    )


@pytest.mark.parametrize(
    "body",
    ["{not valid json", '["a JSON list, not an object"]', '{"entries": 5}', "{}"],
    ids=["unparseable", "top-list", "entries-int", "no-entries-key"],
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


# --- PR #652 review: the exit-code contract past parse time -----------------


@pytest.fixture
def fixture_repo(tmp_path, monkeypatch):
    """A repo root `mutate.main` resolves spec paths against, the same
    `REPO_ROOT` patch `selftest.check_restore_failed_is_observable` uses."""
    (tmp_path / "m.py").write_text('TOKEN = "real"\n')
    monkeypatch.setattr(mutate, "REPO_ROOT", tmp_path)
    return tmp_path


def test_a_spec_naming_a_nonexistent_path_exits_2_before_any_gate_runs(fixture_repo):
    marker = fixture_repo / "gate-ran"
    spec_path = fixture_repo / "spec.toml"
    spec_path.write_text(_spec_text(path="typo.py", gate=f"touch {marker}"))

    code, out, err = _run([str(spec_path), "--journal-dir", str(fixture_repo / "j")])

    assert code == 2
    assert "not an existing file" in err
    assert not marker.exists(), "the baseline gate ran for a spec that could never run"


def test_a_harness_error_mid_run_exits_4_with_the_partial_table_and_a_traceback(
    fixture_repo, monkeypatch
):
    def exploding(specs, repo_root, journal_dir):
        try:
            raise RuntimeError("probe interpreter vanished")
        except RuntimeError as exc:
            raise RunAborted("row M1: RuntimeError: probe interpreter vanished", (),
                             restore_failed=False) from exc

    monkeypatch.setattr(mutate, "run_mutations", exploding)
    spec_path = fixture_repo / "spec.toml"
    spec_path.write_text(_spec_text())

    code, out, err = _run([str(spec_path), "--journal-dir", str(fixture_repo / "j")])

    assert code == 4
    assert out.startswith("| # | Mutation |"), "the (empty) table is still rendered"
    assert "Traceback" in err and "probe interpreter vanished" in err
    assert "mutate: ABORTED" in err


def test_a_non_success_row_prints_its_diagnostic_to_stderr(fixture_repo):
    """The five-column table stays as it was; the reason goes to stderr."""
    (fixture_repo / "m.py").write_text(
        'class Rejection:\n    """doc"""\n\n    TOKEN = "real"\n'
    )
    spec_path = fixture_repo / "spec.toml"
    spec_path.write_text(
        "[[mutation]]\n"
        'id = "DEAD"\n'
        'lang = "python"\n'
        'path = "m.py"\n'
        'old = "class Rejection:"\n'
            'new = "class Rejection:\\n    TOKEN = \\"mutated\\""\n'
        'gate = "true"\n'
        'expect = "red"\n'
        'probe = { module = "m", expr = "Rejection.TOKEN", equals = "mutated", syspath = "." }\n'
    )

    code, out, err = _run([str(spec_path), "--journal-dir", str(fixture_repo / "j")])

    assert code == 1
    assert "| DEAD |" in out and "NOT_LIVE" in out
    assert "DEAD: NOT_LIVE" in err and "did NOT change" in err


def test_an_all_success_run_prints_no_diagnostics(fixture_repo):
    spec_path = fixture_repo / "spec.toml"
    spec_path.write_text(_spec_text())

    code, out, err = _run([str(spec_path), "--journal-dir", str(fixture_repo / "j")])

    assert code == 0, err
    assert "GREEN_AS_EXPECTED" in out
    assert err == ""
