"""A Rust probe can name an integration-test TARGET and FEATURES to build.

Until this, the Rust liveness reading was always `cargo build --release -p
<package>`, which builds the package's LIBRARY and nothing else. A mutation in
a file only an integration test compiles — anything under `core/tests/` — can
never change those artifacts, so every such row read `NOT_LIVE` whatever the
gate did. Measured on the #649 split: `tokens_agree` made strict at its new
path reddened both tests the row named, and the row still reported `NOT_LIVE`,
"artifact contents unchanged across 2 file(s)". The harness was right to
refuse — it could not see the change — but it left every `core/tests/**`
mutation unprovable, including the feature-gated `differential_replay` binary
that is a blocking CI step.

The keys are optional, so every existing spec builds exactly what it built
before; `test_the_default_build_is_unchanged` pins that byte for byte.
"""

import pytest

from mutation_harness import liveness, runner
from mutation_harness.spec import SpecError, parse_spec
from mutation_harness.subproc import BoundedRun
from mutation_harness.types import Expect, Lang, MutationSpec, RustProbe

_SPEC_TEMPLATE = """
[[mutation]]
id = "R1"
lang = "rust"
path = "a.rs"
old = "fn f"
new = "fn g"
gate = "true"
expect = "red"
probe = {probe}
"""


_FEATURES_MSG = "features must be a list of non-empty strings"


def _parse_probe(tmp_path, probe_text: str) -> RustProbe:
    (tmp_path / "a.rs").write_text("fn f() {}\n")
    (spec,) = parse_spec(_SPEC_TEMPLATE.format(probe=probe_text), tmp_path)
    return spec.probe


def test_a_probe_may_name_a_test_target_and_its_features(tmp_path):
    probe = _parse_probe(
        tmp_path,
        '{ package = "demo", test = "differential_replay", features = ["differential-replay"] }',
    )
    assert probe == RustProbe(
        package="demo", test="differential_replay", features=("differential-replay",)
    )


def test_a_probe_naming_only_its_package_scopes_nothing(tmp_path):
    probe = _parse_probe(tmp_path, '{ package = "demo" }')
    assert probe.test is None
    assert probe.features == ()


@pytest.mark.parametrize(
    "probe_text, match",
    [
        ('{ package = "demo", test = "" }', "test must be a non-empty string"),
        ('{ package = "demo", test = 3 }', "test must be a non-empty string"),
        ('{ package = "demo", features = "differential-replay" }', _FEATURES_MSG),
        ('{ package = "demo", features = [""] }', _FEATURES_MSG),
        ('{ package = "demo", features = [1] }', _FEATURES_MSG),
        ('{ package = "demo", features = ["a,b"] }', _FEATURES_MSG),
        ('{ test = "t" }', "missing"),
        ('{ package = "demo", tests = "t" }', "unknown probe key"),
    ],
    ids=["empty-test", "non-string-test", "bare-string-features", "empty-feature",
         "non-string-feature", "comma-in-a-feature", "no-package", "typo-key"],
)
def test_a_malformed_scope_is_refused_rather_than_silently_widened(tmp_path, probe_text, match):
    """An empty or mistyped scope would reach cargo as written (`--test ""`),
    fail the baseline build and report `NOT_LIVE` for a reason the row does
    not name — or, for a typo'd key, build less than the author asked for."""
    with pytest.raises(SpecError, match=match):
        _parse_probe(tmp_path, probe_text)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"package": ""},
        {"package": "demo", "test": ""},
        {"package": "demo", "test": 3},
        {"package": "demo", "features": ["differential-replay"]},
        {"package": "demo", "features": ("",)},
        {"package": "demo", "features": ("a,b",)},
    ],
    ids=["empty-package", "empty-test", "non-string-test", "list-features",
         "empty-feature", "comma-in-a-feature"],
)
def test_a_probe_built_directly_refuses_what_the_spec_parser_refuses(kwargs):
    """`spec.py` is not the only constructor: the controls, the self-test and
    these tests build `RustProbe` directly, and until the #662 review nothing
    stopped them building a scope the parser would refuse."""
    with pytest.raises(ValueError):
        RustProbe(**kwargs)


def test_the_default_build_is_unchanged():
    assert liveness.rust_build_argv(RustProbe("secretary-core")) == [
        "cargo", "build", "--release", "-p", "secretary-core", "--message-format=json",
    ]


def test_a_scoped_probe_builds_that_test_target_with_its_features():
    probe = RustProbe("secretary-core", test="differential_replay", features=("a", "b"))
    assert liveness.rust_build_argv(probe) == [
        "cargo", "build", "--release", "-p", "secretary-core",
        "--features", "a,b", "--test", "differential_replay", "--message-format=json",
    ]


def test_rust_artifact_hashes_runs_the_argv_its_probe_names(tmp_path, monkeypatch):
    """The plumbing, not just the builder: a scope dropped between the probe
    and the subprocess would build the library and read `NOT_LIVE` again."""
    captured = {}

    def fake(argv, **kwargs):
        captured["argv"] = argv
        return BoundedRun(0, "", "")

    monkeypatch.setattr(liveness, "run_bounded", fake)
    probe = RustProbe("secretary-core", test="differential_replay", features=("x",))

    liveness.rust_artifact_hashes(probe, tmp_path)

    assert captured["argv"] == liveness.rust_build_argv(probe)


def test_the_runner_hands_the_whole_probe_to_the_rust_reading(tmp_path, monkeypatch):
    """`_observe` used to pass `spec.probe.package` alone. Passing the probe is
    what carries `test` and `features` through; this pins that it does."""
    seen = []
    monkeypatch.setattr(runner, "rust_artifact_hashes", lambda probe, root: seen.append(probe))
    probe = RustProbe("demo", test="t", features=("f",))
    spec = MutationSpec(
        id="R", lang=Lang.RUST, path="a.rs", old="a", new="b", gate="true",
        expect=Expect.RED, probe=probe,
    )

    runner._observe(spec, tmp_path)

    assert seen == [probe]
