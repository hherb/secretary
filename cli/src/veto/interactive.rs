//! Interactive TTY veto UX. Prompts per-record `y` (KeepLocal) /
//! `n` (AcceptTombstone); re-prompts on invalid input.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §"Public surface" / §D4.
//!
//! Generic over `BufRead + Write` so tests can drive the prompt with
//! [`std::io::Cursor`]s and verify reply parsing without touching a
//! real TTY. Production wires `std::io::stdin().lock()` (read) +
//! `std::io::stderr().lock()` (write) — replies on stderr keep stdout
//! clean for JSON / scriptable output if Task 9 introduces it.

use std::io::{BufRead, Write};

use secretary_core::sync::{RecordTombstoneVeto, VetoDecision};

use super::VetoUx;

/// Default reply for empty input AND for I/O errors mid-read.
///
/// Spec §D4 defines `KeepLocal` as the safe default — it preserves the
/// local record (recoverable: operator can re-run and decide again),
/// whereas `AcceptTombstone` is irreversible. We therefore treat both
/// "operator hit Enter" and "stdin pipe broke / closed early" as
/// `KeepLocal` rather than panicking or escalating. The operator sees
/// the prompt and can interrupt with Ctrl-C if they want to abort
/// before the commit lands.
const DEFAULT_DECISION_LABEL: &str = "KeepLocal";

/// TTY veto UX, generic over any [`BufRead`] + [`Write`] pair for
/// testability. Production wires `stdin().lock()` + `stderr().lock()`;
/// [`crate::pipeline::run_one`] consumes it via `&mut dyn VetoUx`.
pub struct TtyVetoUx<R: BufRead, W: Write> {
    reader: R,
    writer: W,
}

impl<R: BufRead, W: Write> TtyVetoUx<R, W> {
    pub fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

impl<R: BufRead, W: Write> VetoUx for TtyVetoUx<R, W> {
    fn decide(&mut self, vetoes: &[RecordTombstoneVeto]) -> Vec<VetoDecision> {
        let mut out: Vec<VetoDecision> = Vec::with_capacity(vetoes.len());
        // EOF (`read_line` → `Ok(0)`) is final: no further reply can ever
        // arrive on this reader. Track whether we've already surfaced
        // that to the operator so we emit the breadcrumb at most once
        // even when several vetoes default in sequence.
        let mut eof_logged = false;
        for veto in vetoes {
            loop {
                // Prompt-write failures (`writeln!`, `flush`) are
                // intentionally swallowed: if stderr is dead but stdin
                // is alive, the operator may be typing blind, but the
                // decision they enter still propagates correctly. The
                // alternative (panic on broken stderr) would be a worse
                // UX than degraded prompts in a session that's already
                // half-broken.
                let _ = writeln!(
                    self.writer,
                    "Record {} would be tombstoned by peer. Keep local? [y/n] (empty = {DEFAULT_DECISION_LABEL})",
                    crate::state::canonical_hex(veto.record_id)
                );
                let _ = self.writer.flush();
                let mut line = String::new();
                let read = self.reader.read_line(&mut line);
                if read.is_err() {
                    // I/O error reading the reply: conservative
                    // safe-default per `DEFAULT_DECISION_LABEL`. Errors
                    // may be transient (interrupted syscall etc.), so
                    // subsequent vetoes still prompt — only the current
                    // one defaults.
                    out.push(VetoDecision::KeepLocal {
                        record_id: veto.record_id,
                    });
                    break;
                }
                if matches!(read, Ok(0)) && !eof_logged {
                    // First EOF observed: emit one explanatory line so
                    // an operator whose stderr is still readable can
                    // tell their session degraded into auto-default
                    // mode (rather than guessing why subsequent prompts
                    // got no answer). Falls through to the empty-line
                    // branch below which records KeepLocal.
                    let _ = writeln!(
                        self.writer,
                        "  (stdin closed; remaining vetoes default to {DEFAULT_DECISION_LABEL})"
                    );
                    let _ = self.writer.flush();
                    eof_logged = true;
                }
                let trimmed = line.trim();
                match trimmed {
                    "y" | "Y" | "yes" | "" => {
                        out.push(VetoDecision::KeepLocal {
                            record_id: veto.record_id,
                        });
                        break;
                    }
                    "n" | "N" | "no" => {
                        out.push(VetoDecision::AcceptTombstone {
                            record_id: veto.record_id,
                        });
                        break;
                    }
                    _ => {
                        let _ = writeln!(self.writer, "  (please answer y or n)");
                    }
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::dummy_veto;
    use super::*;
    use std::io::{BufReader, Cursor};

    /// Convenience: wrap a scripted reply byte string into the
    /// `BufReader<Cursor<Vec<u8>>>` shape the UX expects.
    fn make_ux(replies: &[u8]) -> TtyVetoUx<BufReader<Cursor<Vec<u8>>>, Cursor<Vec<u8>>> {
        let reader = BufReader::new(Cursor::new(replies.to_vec()));
        let writer = Cursor::new(Vec::<u8>::new());
        TtyVetoUx::new(reader, writer)
    }

    #[test]
    fn scripted_y_returns_keep_local() {
        let mut ux = make_ux(b"y\n");
        let decisions = ux.decide(&[dummy_veto(1)]);
        assert_eq!(decisions.len(), 1);
        assert!(matches!(decisions[0], VetoDecision::KeepLocal { .. }));
    }

    #[test]
    fn scripted_n_returns_accept_tombstone() {
        let mut ux = make_ux(b"n\n");
        let decisions = ux.decide(&[dummy_veto(1)]);
        assert_eq!(decisions.len(), 1);
        assert!(matches!(decisions[0], VetoDecision::AcceptTombstone { .. }));
    }

    #[test]
    fn scripted_uppercase_y_returns_keep_local() {
        let mut ux = make_ux(b"Y\n");
        let decisions = ux.decide(&[dummy_veto(1)]);
        assert!(matches!(decisions[0], VetoDecision::KeepLocal { .. }));
    }

    #[test]
    fn scripted_word_yes_returns_keep_local() {
        let mut ux = make_ux(b"yes\n");
        let decisions = ux.decide(&[dummy_veto(1)]);
        assert!(matches!(decisions[0], VetoDecision::KeepLocal { .. }));
    }

    #[test]
    fn scripted_word_no_returns_accept_tombstone() {
        let mut ux = make_ux(b"no\n");
        let decisions = ux.decide(&[dummy_veto(1)]);
        assert!(matches!(decisions[0], VetoDecision::AcceptTombstone { .. }));
    }

    #[test]
    fn scripted_empty_line_defaults_to_keep_local() {
        let mut ux = make_ux(b"\n");
        let decisions = ux.decide(&[dummy_veto(1)]);
        assert!(matches!(decisions[0], VetoDecision::KeepLocal { .. }));
    }

    #[test]
    fn scripted_eof_with_no_input_defaults_to_keep_local() {
        // Empty reply stream — read_line returns Ok(0) immediately,
        // line stays "", trim is "", match falls into the empty-line
        // branch which is KeepLocal (the documented safe default).
        let mut ux = make_ux(b"");
        let decisions = ux.decide(&[dummy_veto(1)]);
        assert!(matches!(decisions[0], VetoDecision::KeepLocal { .. }));
    }

    #[test]
    fn eof_emits_breadcrumb_once_and_defaults_remaining_to_keep_local() {
        // Closed stdin + multiple vetoes: every decision must default
        // to KeepLocal (safe per spec §D4) AND the operator-facing
        // breadcrumb must appear exactly once even though three vetoes
        // hit Ok(0) in sequence (the `eof_logged` latch).
        let mut ux = make_ux(b"");
        let decisions = ux.decide(&[dummy_veto(1), dummy_veto(2), dummy_veto(3)]);
        assert_eq!(decisions.len(), 3);
        for d in &decisions {
            assert!(matches!(d, VetoDecision::KeepLocal { .. }));
        }
        let written = String::from_utf8(ux.writer.into_inner()).expect("UTF-8");
        let needle = "(stdin closed; remaining vetoes default to KeepLocal)";
        let count = written.matches(needle).count();
        assert_eq!(
            count, 1,
            "expected EOF breadcrumb exactly once, found {count}; output:\n{written}"
        );
    }

    #[test]
    fn invalid_input_reprompts_then_accepts_valid() {
        let mut ux = make_ux(b"maybe\ny\n");
        let decisions = ux.decide(&[dummy_veto(1)]);
        assert_eq!(decisions.len(), 1);
        assert!(matches!(decisions[0], VetoDecision::KeepLocal { .. }));
    }

    #[test]
    fn invalid_input_reprompt_writes_hint_to_writer() {
        let mut ux = make_ux(b"huh\nn\n");
        let _ = ux.decide(&[dummy_veto(1)]);
        // Drain the writer back out — Cursor lets us inspect the
        // bytes that would have gone to stderr in production.
        let written: Vec<u8> = ux.writer.into_inner();
        let text = String::from_utf8(written).expect("prompt bytes must be UTF-8");
        assert!(
            text.contains("(please answer y or n)"),
            "expected re-prompt hint in prompt output, got:\n{text}"
        );
    }

    #[test]
    fn multiple_vetoes_match_input_order_and_record_ids() {
        let mut ux = make_ux(b"y\nn\ny\n");
        let vetoes = vec![dummy_veto(1), dummy_veto(2), dummy_veto(3)];
        let decisions = ux.decide(&vetoes);
        assert_eq!(decisions.len(), 3);
        // Order preserved AND each decision's record_id matches its
        // corresponding veto's record_id (the bijection that
        // commit_with_decisions enforces downstream).
        match &decisions[0] {
            VetoDecision::KeepLocal { record_id } => assert_eq!(*record_id, vetoes[0].record_id),
            other => panic!("expected KeepLocal at [0], got {other:?}"),
        }
        match &decisions[1] {
            VetoDecision::AcceptTombstone { record_id } => {
                assert_eq!(*record_id, vetoes[1].record_id);
            }
            other => panic!("expected AcceptTombstone at [1], got {other:?}"),
        }
        match &decisions[2] {
            VetoDecision::KeepLocal { record_id } => assert_eq!(*record_id, vetoes[2].record_id),
            other => panic!("expected KeepLocal at [2], got {other:?}"),
        }
    }

    #[test]
    fn empty_veto_slice_returns_empty_without_touching_io() {
        let mut ux = make_ux(b"");
        let decisions = ux.decide(&[]);
        assert!(decisions.is_empty());
    }
}
