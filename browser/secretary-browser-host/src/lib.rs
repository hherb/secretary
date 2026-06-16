#![forbid(unsafe_code)]
//! `secretary-browser-host` — the Secretary browser-autofill native-messaging
//! host.
//!
//! The browser spawns this host as a subprocess and exchanges length-prefixed
//! JSON frames over its stdin/stdout. **There is no listening socket** — that
//! structural property (threat-model §6 invariant 3) is the whole point of the
//! D.4.1 slice this host grew from.
//!
//! As of **D.4.2** the host answers a `query` by opening the configured
//! **casual** vault per fill via the existing B.2 / ADR 0009 device-slot path
//! and returning a candidate count ([`vault::per_fill_count`]). It holds no key
//! material between fills, opens only the casual vault, and **no secrets cross
//! the channel** — the reply is an integer count. Credential injection is
//! D.4.4; real origin matching is D.4.3.

pub mod config;
pub mod enroll;
pub mod frame;
pub mod origin;
pub mod origin_match;
pub mod protocol;
pub mod secret_source;
pub mod vault;

#[cfg(test)]
pub(crate) mod test_support;

use std::io::{Read, Write};

use config::{ConfigError, HostConfig};
use frame::FrameError;
use protocol::{Inbound, Outbound};
use secret_source::{DeviceSecretSource, SecretSourceError};

/// Per-process host state: the enrollment binding, if this browser is enrolled.
///
/// The context holds the [`DeviceSecretSource`] *port*, never the secret
/// itself — the secret is fetched per fill and dropped immediately, so the host
/// holds no key material between fills (design §12 invariant 1). An
/// **un-enrolled** context answers every query with `count: 0` (no affordance),
/// which is the correct, non-failing posture for a browser the user hasn't
/// opted into.
pub struct Context {
    enrolled: Option<Enrolled>,
}

struct Enrolled {
    config: HostConfig,
    source: Box<dyn DeviceSecretSource>,
}

impl Context {
    /// A context for a browser that is **not** enrolled — every query → `count: 0`.
    pub fn not_enrolled() -> Self {
        Self { enrolled: None }
    }

    /// A context bound to a casual vault + secret source.
    pub fn new(config: HostConfig, source: Box<dyn DeviceSecretSource>) -> Self {
        Self {
            enrolled: Some(Enrolled { config, source }),
        }
    }

    /// Build the context from the helper-local config (or not-enrolled if no
    /// config file exists). A malformed config is a hard error — the host
    /// should not silently run un-enrolled when the user *did* configure it.
    pub fn from_default_config() -> Result<Self, ConfigError> {
        match HostConfig::load_default()? {
            Some(config) => {
                let source = config.build_secret_source();
                Ok(Self::new(config, source))
            }
            None => Ok(Self::not_enrolled()),
        }
    }

    /// Answer one inbound message.
    fn answer(&self, message: Inbound) -> Outbound {
        match message {
            Inbound::Query { .. } => self.answer_query(),
            Inbound::Unknown => Outbound::error("unknown or unsupported message type"),
        }
    }

    /// A `query` → an `available { count }` (or an `error` on a genuine
    /// open/config failure of an enrolled vault).
    fn answer_query(&self) -> Outbound {
        let Some(enrolled) = &self.enrolled else {
            // Not enrolled: no affordance, never an error.
            return Outbound::available_none();
        };
        match vault::per_fill_count(&enrolled.config, enrolled.source.as_ref()) {
            Ok(count) => Outbound::available(count),
            // The secret simply isn't present yet (e.g. file not written, or a
            // keystore item the user hasn't unlocked). Treat as "no affordance"
            // rather than a hard error — same posture as un-enrolled.
            Err(vault::PerFillError::Secret(SecretSourceError::Unavailable(_))) => {
                Outbound::available_none()
            }
            // A genuine misconfiguration or open failure of a configured vault:
            // surface it as an error so it is visible, not silently zero.
            Err(e) => Outbound::error(format!("per-fill open failed: {e}")),
        }
    }
}

/// Run the read→dispatch→write loop until the input stream ends.
///
/// One iteration: decode an [`Inbound`] frame, answer it against `ctx`, encode
/// the [`Outbound`] reply, and flush. The loop terminates cleanly when the
/// browser closes the host's stdin (a clean EOF at a frame boundary).
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
pub fn run<R: Read, W: Write>(
    ctx: &Context,
    reader: &mut R,
    writer: &mut W,
) -> std::io::Result<()> {
    loop {
        match frame::decode::<Inbound, _>(reader) {
            // Clean shutdown: the browser closed stdin at a frame boundary.
            Ok(None) => return Ok(()),
            Ok(Some(message)) => {
                write_frame(writer, &ctx.answer(message))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use test_support::{config_for, enrolled_golden, FakeSource};

    fn query_frame() -> Vec<u8> {
        let mut buf = Vec::new();
        frame::encode(
            &mut buf,
            &serde_json::json!({
                "type": "query",
                "top_origin": "https://example.com",
                "frame_origin": "https://example.com",
                "https": true,
            }),
        )
        .unwrap();
        buf
    }

    #[test]
    fn not_enrolled_query_is_available_zero() {
        let ctx = Context::not_enrolled();
        match ctx.answer(Inbound::Query {
            top_origin: "https://example.com".into(),
            frame_origin: "https://example.com".into(),
            https: true,
        }) {
            Outbound::Available { count, .. } => assert_eq!(count, 0),
            other => panic!("expected Available, got {other:?}"),
        }
    }

    #[test]
    fn unknown_is_error_regardless_of_enrollment() {
        let ctx = Context::not_enrolled();
        assert!(matches!(
            ctx.answer(Inbound::Unknown),
            Outbound::Error { .. }
        ));
    }

    #[test]
    fn enrolled_query_counts_blocks() {
        let (_tmp, vault, uuid, secret) = enrolled_golden();
        let cfg = config_for(&vault, &uuid);
        let expected = vault::per_fill_count(&cfg, &FakeSource(secret.clone())).unwrap();

        let ctx = Context::new(cfg, Box::new(FakeSource(secret)));
        match ctx.answer(Inbound::Query {
            top_origin: "https://example.com".into(),
            frame_origin: "https://example.com".into(),
            https: true,
        }) {
            Outbound::Available { count, .. } => assert_eq!(count, expected),
            other => panic!("expected Available, got {other:?}"),
        }
    }

    #[test]
    fn enrolled_with_wrong_secret_is_error() {
        let (_tmp, vault, uuid, _secret) = enrolled_golden();
        let cfg = config_for(&vault, &uuid);
        let mut wrong = vec![0u8; secret_source::DEVICE_SECRET_LEN];
        for (i, b) in wrong.iter_mut().enumerate() {
            *b = (i as u8) ^ 0x5A;
        }
        let ctx = Context::new(cfg, Box::new(FakeSource(wrong)));
        assert!(matches!(
            ctx.answer(Inbound::Query {
                top_origin: "https://example.com".into(),
                frame_origin: "https://example.com".into(),
                https: true,
            }),
            Outbound::Error { .. }
        ));
    }

    #[test]
    fn run_end_to_end_enrolled_emits_available_count() {
        let (_tmp, vault, uuid, secret) = enrolled_golden();
        let cfg = config_for(&vault, &uuid);
        let expected = vault::per_fill_count(&cfg, &FakeSource(secret.clone())).unwrap();
        let ctx = Context::new(cfg, Box::new(FakeSource(secret)));

        let mut reader = Cursor::new(query_frame());
        let mut writer = Vec::new();
        run(&ctx, &mut reader, &mut writer).unwrap();

        let mut out = Cursor::new(writer);
        let reply: Outbound = frame::decode(&mut out).unwrap().unwrap();
        match reply {
            Outbound::Available { count, .. } => assert_eq!(count, expected),
            other => panic!("expected Available, got {other:?}"),
        }
    }
}
