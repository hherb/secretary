//! Length-prefixed framing codec for the browser native-messaging transport.
//!
//! Native messaging frames each message as a **4-byte length prefix in the
//! host's native byte order** followed by exactly that many bytes of UTF-8
//! JSON. The browser spawns the host and exchanges these frames over the
//! host's stdin/stdout — **there is no socket** (threat-model §6 invariant 3).
//!
//! The codec is the load-bearing, testable core of D.4.1. It upholds two
//! contracts:
//!
//! * **Never panics on malformed input.** A bad length, a short read, or a
//!   non-JSON body is a typed [`FrameError`], not a crash — mirroring the
//!   fuzz-harness "assert `Result`, not panic" discipline (see CLAUDE.md).
//! * **Caps every frame at [`MAX_FRAME_LEN`] (1 MiB).** An oversized length
//!   prefix is rejected *before* any buffer is allocated, bounding host-side
//!   memory against a hostile or buggy peer.

use std::io::{self, Read, Write};

use serde::{de::DeserializeOwned, Serialize};

/// Maximum frame size, in bytes (1 MiB).
///
/// This matches the Chromium native-messaging host→extension cap; we apply it
/// symmetrically to the extension→host direction so a malicious or buggy
/// extension cannot make the host allocate an unbounded buffer.
pub const MAX_FRAME_LEN: usize = 1024 * 1024;

/// A typed framing error. Every malformed-input path returns one of these
/// rather than panicking.
#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    /// The declared (decode) or serialized (encode) frame length exceeds
    /// [`MAX_FRAME_LEN`]. Carries the offending length so callers can log it.
    #[error("frame length {0} bytes exceeds the {MAX_FRAME_LEN}-byte cap")]
    TooLarge(u64),

    /// The frame body was not valid JSON for the target type.
    #[error("malformed JSON frame body: {0}")]
    Json(#[from] serde_json::Error),

    /// An underlying I/O error, including a truncated frame (a partial length
    /// prefix or a body shorter than its declared length surfaces here as
    /// [`io::ErrorKind::UnexpectedEof`]).
    #[error("frame I/O error: {0}")]
    Io(#[from] io::Error),
}

/// Outcome of reading the 4-byte length prefix.
enum LenRead {
    /// Clean shutdown: zero bytes were available before any prefix byte.
    Eof,
    /// A partial prefix (1–3 bytes) then EOF — a truncated frame.
    Truncated,
    /// All four prefix bytes were read.
    Full,
}

/// Read exactly four length bytes, distinguishing a clean stream end from a
/// truncated prefix. `Interrupted` is retried per the standard `Read` contract.
fn read_len_prefix<R: Read>(reader: &mut R, buf: &mut [u8; 4]) -> io::Result<LenRead> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => {
                return Ok(if filled == 0 {
                    LenRead::Eof
                } else {
                    LenRead::Truncated
                });
            }
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(LenRead::Full)
}

/// Decode a single length-prefixed JSON frame from `reader`.
///
/// Returns:
/// * `Ok(Some(value))` — a complete frame was read and parsed.
/// * `Ok(None)` — the stream ended cleanly at a frame boundary (no bytes
///   pending). This is the host's normal shutdown signal: the browser closed
///   stdin.
/// * `Err(FrameError::TooLarge)` — the declared length exceeds [`MAX_FRAME_LEN`]
///   (rejected before allocating the body buffer).
/// * `Err(FrameError::Io)` — a truncated prefix/body or other I/O failure.
/// * `Err(FrameError::Json)` — the body was not valid JSON for `T`.
pub fn decode<T, R>(reader: &mut R) -> Result<Option<T>, FrameError>
where
    T: DeserializeOwned,
    R: Read,
{
    let mut len_buf = [0u8; 4];
    match read_len_prefix(reader, &mut len_buf)? {
        LenRead::Eof => return Ok(None),
        LenRead::Truncated => {
            return Err(FrameError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated frame length prefix",
            )));
        }
        LenRead::Full => {}
    }

    let len = u32::from_ne_bytes(len_buf) as usize;
    // Validate the cap *before* allocating so a hostile 4-byte prefix cannot
    // make us reserve up to 4 GiB.
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len as u64));
    }

    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    let value = serde_json::from_slice(&body)?;
    Ok(Some(value))
}

/// Encode `value` as a length-prefixed JSON frame and write it to `writer`.
///
/// Returns [`FrameError::TooLarge`] if the serialized body exceeds
/// [`MAX_FRAME_LEN`] (so the host can never emit a frame the peer would reject).
pub fn encode<T, W>(writer: &mut W, value: &T) -> Result<(), FrameError>
where
    T: Serialize,
    W: Write,
{
    let body = serde_json::to_vec(value)?;
    if body.len() > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(body.len() as u64));
    }
    // `body.len() <= MAX_FRAME_LEN` (1 MiB) fits in u32 on every platform.
    let len = body.len() as u32;
    writer.write_all(&len.to_ne_bytes())?;
    writer.write_all(&body)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::io::Cursor;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Msg {
        kind: String,
        n: u32,
    }

    #[test]
    fn round_trip_encode_decode() {
        let msg = Msg {
            kind: "query".to_string(),
            n: 7,
        };
        let mut buf = Vec::new();
        encode(&mut buf, &msg).expect("encode");

        // The 4-byte native-endian prefix must equal the body length.
        let body_len = buf.len() - 4;
        let prefix = u32::from_ne_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(prefix, body_len);

        let mut cursor = Cursor::new(buf);
        let decoded: Option<Msg> = decode(&mut cursor).expect("decode");
        assert_eq!(decoded, Some(msg));
    }

    #[test]
    fn clean_eof_returns_none() {
        let mut cursor = Cursor::new(Vec::<u8>::new());
        let decoded: Option<Msg> = decode(&mut cursor).expect("clean EOF is not an error");
        assert!(decoded.is_none());
    }

    #[test]
    fn truncated_length_prefix_is_io_error() {
        // Only two of the four prefix bytes are present, then EOF.
        let mut cursor = Cursor::new(vec![0x01u8, 0x00]);
        let err = decode::<Msg, _>(&mut cursor).expect_err("truncated prefix must error");
        match err {
            FrameError::Io(e) => assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof),
            other => panic!("expected Io(UnexpectedEof), got {other:?}"),
        }
    }

    #[test]
    fn truncated_body_is_io_error() {
        // Declared length 8, but only 3 body bytes follow.
        let mut frame = 8u32.to_ne_bytes().to_vec();
        frame.extend_from_slice(b"abc");
        let mut cursor = Cursor::new(frame);
        let err = decode::<Msg, _>(&mut cursor).expect_err("truncated body must error");
        assert!(matches!(err, FrameError::Io(_)));
    }

    #[test]
    fn oversize_length_is_rejected_without_allocating() {
        // A 4-byte prefix declaring MAX + 1 bytes, with no body following.
        // Decode must reject on the prefix alone (never trying to read or
        // allocate the body), so the missing body does not matter.
        let oversize = (MAX_FRAME_LEN as u32) + 1;
        let frame = oversize.to_ne_bytes().to_vec();
        let mut cursor = Cursor::new(frame);
        let err = decode::<Msg, _>(&mut cursor).expect_err("oversize length must error");
        match err {
            FrameError::TooLarge(n) => assert_eq!(n, oversize as u64),
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn max_length_is_accepted() {
        // Boundary: a frame of exactly MAX_FRAME_LEN bytes must be allowed.
        let body = vec![b'x'; MAX_FRAME_LEN];
        let mut frame = (MAX_FRAME_LEN as u32).to_ne_bytes().to_vec();
        frame.extend_from_slice(&body);
        let mut cursor = Cursor::new(frame);
        // The body is not valid JSON, so decoding into `Msg` fails at the JSON
        // step — proving the length cap accepted it rather than rejecting it.
        let err = decode::<Msg, _>(&mut cursor).expect_err("non-JSON body");
        assert!(matches!(err, FrameError::Json(_)));
    }

    #[test]
    fn non_json_body_is_json_error() {
        let body = b"this is not json";
        let mut frame = (body.len() as u32).to_ne_bytes().to_vec();
        frame.extend_from_slice(body);
        let mut cursor = Cursor::new(frame);
        let err = decode::<Msg, _>(&mut cursor).expect_err("non-JSON body must error");
        assert!(matches!(err, FrameError::Json(_)));
    }

    #[test]
    fn encode_rejects_oversize_body() {
        // A string whose JSON serialization exceeds the 1 MiB cap.
        let big = "a".repeat(MAX_FRAME_LEN + 16);
        let mut buf = Vec::new();
        let err = encode(&mut buf, &big).expect_err("oversize body must be rejected");
        assert!(matches!(err, FrameError::TooLarge(_)));
        // Nothing should have been written — we reject before touching `writer`.
        assert!(buf.is_empty());
    }

    #[test]
    fn two_frames_decode_sequentially() {
        let a = Msg {
            kind: "query".to_string(),
            n: 1,
        };
        let b = Msg {
            kind: "available".to_string(),
            n: 0,
        };
        let mut buf = Vec::new();
        encode(&mut buf, &a).unwrap();
        encode(&mut buf, &b).unwrap();

        let mut cursor = Cursor::new(buf);
        let first: Option<Msg> = decode(&mut cursor).unwrap();
        let second: Option<Msg> = decode(&mut cursor).unwrap();
        let third: Option<Msg> = decode(&mut cursor).unwrap();
        assert_eq!(first, Some(a));
        assert_eq!(second, Some(b));
        assert!(
            third.is_none(),
            "stream should end cleanly after two frames"
        );
    }
}
