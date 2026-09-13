//! Progress lines for the corpus replay, written where libtest cannot hide
//! them (#655).
//!
//! Before this, the full replay printed nothing while it ran, so a corpus of
//! tens of thousands of inputs was indistinguishable from a hang: libtest
//! reports only "has been running for over 60 seconds". Two things make these
//! lines visible where an `eprintln!` would not be:
//!
//! - libtest CAPTURES `print!`/`eprint!` output of a passing test, so the old
//!   per-target `eprintln!` count appeared only under `--nocapture` and a CI
//!   log proved "4 passed" and nothing about how much was replayed (#656
//!   review). These lines go to the process's stderr handle directly, which
//!   the capture does not intercept.
//! - A line per input would bury the log, so a target reports when it starts,
//!   at most every [`PROGRESS_INTERVAL`] while it runs, and when it finishes.

use std::io::Write;
use std::time::{Duration, Instant};

/// The most often a running target reports progress.
pub const PROGRESS_INTERVAL: Duration = Duration::from_secs(10);

pub fn start_line(target: &str, total: usize, committed: usize) -> String {
    format!("[differential_replay] {target}: replaying {total} input(s), {committed} committed")
}

pub fn progress_line(target: &str, done: usize, total: usize, elapsed: Duration) -> String {
    format!(
        "[differential_replay] {target}: {done}/{total} after {:.1}s",
        elapsed.as_secs_f64()
    )
}

pub fn finish_line(target: &str, total: usize, committed: usize, elapsed: Duration) -> String {
    format!(
        "[differential_replay] {target}: replayed {total} input(s), {committed} committed, \
         in {:.1}s",
        elapsed.as_secs_f64()
    )
}

/// Write `line` to the process's stderr handle, bypassing libtest's capture.
pub fn emit(line: &str) {
    // A failed write to stderr is not worth failing the replay over; the
    // verdicts, not these lines, are what the test asserts.
    let _ = writeln!(std::io::stderr(), "{line}");
}

/// Is a progress line due? Pure: `last` is when the previous line was written.
pub fn is_due(last: Instant, now: Instant) -> bool {
    now.saturating_duration_since(last) >= PROGRESS_INTERVAL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_start_line_names_the_target_and_both_counts() {
        let line = start_line("vault_toml", 60931, 3);
        assert!(line.contains("vault_toml"), "{line}");
        assert!(line.contains("60931") && line.contains('3'), "{line}");
    }

    #[test]
    fn a_progress_line_carries_done_of_total() {
        let line = progress_line("record", 1200, 7454, Duration::from_secs(12));
        assert!(
            line.contains("record") && line.contains("1200/7454"),
            "{line}"
        );
    }

    #[test]
    fn a_finish_line_names_both_counts_so_a_ci_log_proves_what_was_replayed() {
        let line = finish_line("manifest_body", 39, 39, Duration::from_millis(1500));
        assert!(
            line.contains("manifest_body") && line.contains("39"),
            "{line}"
        );
        assert!(line.contains("committed"), "{line}");
    }

    #[test]
    fn progress_is_due_only_once_the_interval_has_passed() {
        let last = Instant::now();
        assert!(!is_due(last, last));
        assert!(!is_due(
            last,
            last + PROGRESS_INTERVAL - Duration::from_millis(1)
        ));
        assert!(is_due(last, last + PROGRESS_INTERVAL));
    }
}
