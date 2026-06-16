#![forbid(unsafe_code)]
//! `secretary-browser-host` — the Secretary browser-autofill native-messaging
//! host (D.4.1 walking skeleton).
//!
//! The browser spawns this host as a subprocess and exchanges length-prefixed
//! JSON frames over its stdin/stdout. **There is no listening socket** — that
//! structural property (threat-model §6 invariant 3) is the whole point of the
//! D.4.1 slice.
//!
//! This crate is intentionally **pure transport**: it has **no `secretary-core`
//! dependency**, holds no key material, and opens no vault. D.4.2 attaches the
//! crypto behind the same `open_with_device_secret` verify-before-decrypt path.

pub mod frame;
pub mod protocol;

use std::io::{Read, Write};

use frame::FrameError;
use protocol::{handle, Inbound, Outbound};

/// Run the read→dispatch→write loop until the input stream ends.
///
/// One iteration: decode an [`Inbound`] frame, [`handle`] it, encode the
/// [`Outbound`] reply, and flush. The loop terminates cleanly when the browser
/// closes the host's stdin (a clean EOF at a frame boundary).
///
/// Malformed input never panics or aborts the process silently:
///
/// * **Bad JSON body** — the frame was fully consumed, so the host replies with
///   an [`Outbound::Error`] and keeps serving.
/// * **Oversized length prefix** ([`FrameError::TooLarge`]) — the body was *not*
///   consumed (rejected before allocation), so the stream is now misaligned;
///   the host replies with an error and then stops, since it cannot safely
///   resynchronize.
/// * **Truncated frame / pipe error** ([`FrameError::Io`]) — surfaced to the
///   caller, which exits non-zero.
pub fn run<R: Read, W: Write>(reader: &mut R, writer: &mut W) -> std::io::Result<()> {
    loop {
        match frame::decode::<Inbound, _>(reader) {
            // Clean shutdown: the browser closed stdin at a frame boundary.
            Ok(None) => return Ok(()),
            Ok(Some(message)) => {
                write_frame(writer, &handle(message))?;
            }
            // Body was consumed; the stream is still aligned — recover.
            Err(FrameError::Json(e)) => {
                write_frame(writer, &Outbound::error(format!("malformed frame: {e}")))?;
            }
            // Body was NOT consumed — the stream is misaligned. Report and stop.
            Err(FrameError::TooLarge(n)) => {
                write_frame(
                    writer,
                    &Outbound::error(format!("frame too large ({n} bytes); closing")),
                )?;
                return Ok(());
            }
            // Truncated prefix/body or pipe failure: nothing safe to do but exit.
            Err(FrameError::Io(e)) => return Err(e),
        }
    }
}

/// Encode and flush a single reply frame.
fn write_frame<W: Write>(writer: &mut W, reply: &Outbound) -> std::io::Result<()> {
    frame::encode(writer, reply).map_err(|e| match e {
        FrameError::Io(io) => io,
        // Encoding our own small, well-formed replies cannot exceed the cap or
        // fail to serialize; treat any such impossibility as an I/O fault.
        other => std::io::Error::other(other.to_string()),
    })?;
    writer.flush()
}
