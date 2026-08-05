//! Asserts the Python and bash allowlist parsers agree.
//!
//! The two shell log-hygiene guards share one matcher via
//! `scripts/lib/hygiene-allowlist.sh`; `check-error-payload-hygiene.py` cannot
//! source it, so it reimplements the same exact-trimmed-line semantics. This
//! test makes that duplication non-silent: both parsers consume one fixture and
//! must produce identical accept/reject verdicts (#474).
//!
//! The deliberate departure from #475's extract-don't-duplicate rule is
//! justified because what that rule protected — `is_comment_line`, which had
//! the same bug twice — has no counterpart in a tokenizing parser.

use std::process::Command;

/// Four TAB-separated columns: `<path>\t<rule>\t<exact trimmed line>\t<reason>`.
/// Identical to the two shell guards' allowlists, which is the whole point —
/// `allowlisted()` parses this fixture unmodified.
const FIXTURE: &str = concat!(
    "# a comment line, ignored by both\n",
    "\n",
    "core/src/a.rs\tE1\t#[error(\"x: {0}\")]\treason one\n",
    "core/src/b.rs\tE1\t#[error(\"y: {detail}\")]\treason two\n",
);

#[test]
fn python_and_bash_allowlist_parsers_agree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("fixture-allowlist.txt");
    std::fs::write(&path, FIXTURE).expect("write fixture");

    let probes: &[(&str, &str, bool)] = &[
        ("core/src/a.rs", "#[error(\"x: {0}\")]", true),
        ("core/src/b.rs", "#[error(\"y: {detail}\")]", true),
        // Right line, wrong file.
        ("core/src/a.rs", "#[error(\"y: {detail}\")]", false),
        ("core/src/c.rs", "#[error(\"x: {0}\")]", false),
        // A SUBSTRING of a real entry must NOT match. This is the property
        // whose absence was demonstrably exploitable in #467.
        ("core/src/a.rs", "#[error(\"x:", false),
        // Leading/trailing whitespace is trimmed on both sides, so an
        // indentation change must NOT break a valid entry.
        ("core/src/a.rs", "    #[error(\"x: {0}\")]   ", true),
        ("core/src/a.rs", "# a comment line, ignored by both", false),
    ];

    for &(file, line, expected) in probes {
        let py = probe_python(&path, file, line);
        let sh = probe_bash(&path, file, line);
        assert_eq!(
            py, expected,
            "python parser disagreed with the expectation for ({file}, {line:?})"
        );
        assert_eq!(
            sh, py,
            "bash and python parsers disagreed for ({file}, {line:?})"
        );
    }
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// The Python side keys on `path\trule\ttrimmed-line`, so trim here to mirror
/// what `allowlisted()` does to the hit text before comparing.
fn probe_python(allowlist: &std::path::Path, file: &str, line: &str) -> bool {
    let root = repo_root();
    let key = format!("{file}\tE1\t{}", line.trim());
    let script = r#"
import importlib.util as u, pathlib, sys
spec = u.spec_from_file_location("guard", sys.argv[1])
mod = u.module_from_spec(spec)
sys.modules["guard"] = mod
spec.loader.exec_module(mod)
entries = mod.load_allowlist(pathlib.Path(sys.argv[2]))
print("YES" if sys.argv[3] in entries else "NO")
"#;
    let out = Command::new("uv")
        .args([
            "run",
            "python",
            "-c",
            script,
            &root
                .join("scripts/check-error-payload-hygiene.py")
                .to_string_lossy(),
            &allowlist.to_string_lossy(),
            &key,
        ])
        .current_dir(&root)
        .output()
        .expect("run python probe");
    assert!(
        out.status.success(),
        "python probe exited non-zero: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim() == "YES"
}

/// `allowlisted()` takes `(rule, hit)` where `hit` is `<file>:<line>:<text>`,
/// and reads `$ALLOWLIST` / `$REPO_ROOT` from the SOURCING scope — it does not
/// take them as arguments. `$ALLOWLIST` must not be `readonly`. See the header
/// of `scripts/lib/hygiene-allowlist.sh`.
fn probe_bash(allowlist: &std::path::Path, file: &str, line: &str) -> bool {
    let root = repo_root();
    let out = Command::new("bash")
        .arg("-c")
        .arg(
            r#"set -euo pipefail
source scripts/lib/hygiene-allowlist.sh
if allowlisted "E1" "$1"; then echo YES; else echo NO; fi"#,
        )
        .arg("bash")
        // `<file>:<line-number>:<text>` — allowlisted() strips the first two
        // colon-delimited fields, so the line number is arbitrary.
        .arg(format!("{file}:1:{line}"))
        .env("ALLOWLIST", allowlist)
        .env("REPO_ROOT", &root)
        .current_dir(&root)
        .output()
        .expect("run bash probe");
    assert!(
        out.status.success(),
        "bash probe exited non-zero: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim() == "YES"
}
