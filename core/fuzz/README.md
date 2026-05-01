# Fuzz harness

Coverage-guided fuzz harness for the six wire-format decoders that ingest
attacker-controlled bytes from disk. See the design spec at
[docs/superpowers/specs/2026-04-30-fuzz-harness-design.md](../../docs/superpowers/specs/2026-04-30-fuzz-harness-design.md)
for goals and exit criteria.

## Targets

| Target          | Decoder                                              | Oracle                |
|-----------------|------------------------------------------------------|-----------------------|
| `vault_toml`    | `unlock::vault_toml::decode`                         | crash only            |
| `record`        | `vault::record::decode`                              | crash + roundtrip-eq  |
| `contact_card`  | `identity::card::ContactCard::from_canonical_cbor`   | crash + roundtrip-eq  |
| `bundle_file`   | `unlock::bundle_file::decode`                        | crash + roundtrip-eq  |
| `manifest_file` | `vault::manifest::decode_manifest_file`              | crash + roundtrip-eq  |
| `block_file`    | `vault::block::decode_block_file`                    | crash + roundtrip-eq  |

## One-time setup

```bash
rustup install nightly                  # this dir's rust-toolchain.toml pins nightly
cargo install cargo-fuzz                # uses stable to install the binary
```

If your environment has Homebrew's cargo on PATH that masks rustup's nightly
toolchain (common on macOS), prepend the rustup nightly to PATH for the
duration of `cargo fuzz` invocations:

```bash
PATH="$HOME/.rustup/toolchains/nightly-2026-04-29-aarch64-apple-darwin/bin:$PATH" cargo fuzz <subcommand>
```

(Replace the architecture in the path if you're not on Apple Silicon.)

## Run a target

ASan (default):

```bash
cd core/fuzz
cargo fuzz run <target>
```

UBSan:

```bash
cd core/fuzz
cargo fuzz run --sanitizer=undefined <target>
```

Replay seeds only (no mutation):

```bash
cd core/fuzz
cargo fuzz run <target> seeds/<target>/ -- -runs=0
```

## Calibrated exec-count floors

Per the spec's hardware-independent stop signal, each target has a calibrated
exec-count floor (the floor below which the run is considered too short to
have plateaued). These floors were calibrated on the operator's reference
workstation; reproduce by running each target until libFuzzer reports zero
new `cov` and `corp` for the last >=10% of executions.

| Target          | ASan exec floor | UBSan exec floor | Reference wall-clock (combined) |
|-----------------|-----------------|------------------|---------------------------------|
| `vault_toml`    | _TBD — fill in during Task 12_ | _TBD_ | _TBD_ |
| `record`        | _TBD_           | _TBD_            | _TBD_                           |
| `contact_card`  | _TBD_           | _TBD_            | _TBD_                           |
| `bundle_file`   | _TBD_           | _TBD_            | _TBD_                           |
| `manifest_file` | _TBD_           | _TBD_            | _TBD_                           |
| `block_file`    | _TBD_           | _TBD_            | _TBD_                           |

To run to floor:

```bash
cd core/fuzz
cargo fuzz run <target> -- -runs=<floor>
```

## Promoting a crash to a regression

When `cargo fuzz run` reports a crash, libFuzzer writes the offending input
to `core/fuzz/artifacts/<target>/crash-<hash>`. To promote:

```bash
# 1. Verify reproducibility
cd core/fuzz
cargo fuzz run <target> artifacts/<target>/crash-<hash>

# 2. Minimize
cargo fuzz tmin <target> artifacts/<target>/crash-<hash>
# This produces artifacts/<target>/minimized-from-crash-<hash>.

# 3. Copy to the durable regression dir
cp artifacts/<target>/minimized-from-crash-<hash> \
   ../tests/data/fuzz_regressions/<target>/<descriptive-name>.bin

# 4. Add a sibling .md describing the bug (optional but encouraged)
$EDITOR ../tests/data/fuzz_regressions/<target>/<descriptive-name>.md

# 5. Fix the bug in core/, then verify:
cd ..
cargo test --release --workspace --test fuzz_regressions
```

The regression test runs as part of `cargo test --release --workspace`
unconditionally — it does not depend on the fuzz harness or nightly.

## Monitor (NiceGUI dashboard)

A single-file NiceGUI dashboard at `core/fuzz/monitor.py` provides a
browser UI for kicking off fuzz campaigns and watching them auto-stop
on coverage plateau. Runs at `http://localhost:8080`.

```bash
uv run core/fuzz/monitor.py
```

Per-target card has:
- Sanitizer radio: `asan`, `ubsan`, or `both` (sequential).
- Runs cap input (last value persisted per target in `.monitor-state.json`).
- Start/Stop buttons.
- Live status, coverage, corpus, exec rate, RSS.
- Log tail (last 20 stderr lines).
- On crash: red badge with the crash file path.

Plateau detection: auto-SIGTERM after K=10 consecutive libFuzzer pulse
lines with no growth in `cov` or `corp`. Adjustable in the source if
needed; default works for the six fuzz targets in this repo.

The monitor is operator quality-of-life — the harness it drives stays
fully usable from the CLI (`cargo fuzz run <target>`) for any future
maintainer or auditor. See
[docs/superpowers/specs/2026-05-01-fuzz-monitor-design.md](../../docs/superpowers/specs/2026-05-01-fuzz-monitor-design.md)
for the design rationale.

## Differential replay (out-of-loop)

Runs the accumulated runtime corpus + committed seeds + diff_regressions
through both the Rust decoder and the Python clean-room decoder in
`core/tests/python/conformance.py`, asserting agreement.

```bash
# default cargo test stays Rust-only:
cargo test --release --workspace

# opt in to differential replay (requires uv):
cargo test --release --workspace --features differential-replay
```

A disagreement is one of: Rust bug -> fix Rust; Python bug -> fix Python;
spec ambiguity -> docs PR alongside the fix. Sticky disagreements get
committed as inputs in `core/tests/data/diff_regressions/<target>/`.

For the contract between `differential_replay.rs` and the Python
side (output JSON shapes, accept/reject semantics, how to add a new
target), see
[docs/manual/contributors/differential-replay-protocol.md](../../docs/manual/contributors/differential-replay-protocol.md).
**Read it before changing `core/tests/python/conformance.py`'s
`--diff-replay` mode.**
