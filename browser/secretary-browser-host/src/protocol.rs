//! Wire protocol for the D.4.1 native-messaging walking skeleton.
//!
//! Only the transport-proving subset of the full design (§3) lives here. The
//! extension sends a [`Inbound::Query`]; the host always answers
//! [`Outbound::Available`] with `count: 0` (no matching exists yet — that is
//! D.4.3). An unrecognized message type is answered with [`Outbound::Error`],
//! never a panic.
//!
//! Every reply carries a freshly minted `request_id` so D.4.4's `request_fill`
//! correlation is already threaded through the channel.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A message received from the extension. Internally tagged on `type`.
///
/// Any object whose `type` is not a known variant deserializes to
/// [`Inbound::Unknown`] (via `#[serde(other)]`) rather than failing, so the
/// host can answer with a typed error frame instead of treating a forward- or
/// mis-typed message as a decode crash.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Inbound {
    /// "Is anything available for this page?" The host replies with a count
    /// (always 0 in D.4.1).
    Query {
        /// Origin of the top-level document.
        top_origin: String,
        /// Origin of the frame that triggered the query (may equal `top_origin`).
        frame_origin: String,
        /// Whether the frame was served over HTTPS.
        https: bool,
    },
    /// Any `type` the host does not recognize.
    #[serde(other)]
    Unknown,
}

/// A message sent to the extension. Internally tagged on `type`.
///
/// `Deserialize` is derived purely so tests (and any future host-side
/// self-check) can decode a reply the host wrote; production code only ever
/// serializes `Outbound`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Outbound {
    /// Reply to a [`Inbound::Query`]. `count` is the number of fillable
    /// candidates — always 0 in this slice.
    Available {
        /// Correlation token for a later `request_fill` (D.4.4).
        request_id: String,
        /// Candidate count. Always 0 in D.4.1.
        count: u32,
    },
    /// A message the host could not process (unknown type, malformed frame).
    Error {
        /// Correlation token; present even on error so the extension can tie
        /// the failure back to its request flow.
        request_id: String,
        /// Human-readable, non-sensitive description of what went wrong.
        message: String,
    },
}

impl Outbound {
    /// Build an `available { count }` reply with a fresh `request_id`.
    pub fn available(count: u32) -> Self {
        Outbound::Available {
            request_id: new_request_id(),
            count,
        }
    }

    /// Build an `available { count: 0 }` reply with a fresh `request_id`.
    pub fn available_none() -> Self {
        Self::available(0)
    }

    /// Build an `error` reply with a fresh `request_id`.
    pub fn error(message: impl Into<String>) -> Self {
        Outbound::Error {
            request_id: new_request_id(),
            message: message.into(),
        }
    }
}

/// Dispatch one inbound message to its reply. Pure and total — every input,
/// including [`Inbound::Unknown`], maps to an [`Outbound`].
pub fn handle(message: Inbound) -> Outbound {
    match message {
        // No matching exists yet (D.4.3), so the host always reports zero.
        Inbound::Query { .. } => Outbound::available_none(),
        Inbound::Unknown => Outbound::error("unknown or unsupported message type"),
    }
}

/// Mint a fresh random (v4) request-correlation id, hyphenated lowercase.
fn new_request_id() -> String {
    Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_deserializes() {
        let json = r#"{"type":"query","top_origin":"https://example.com",
                       "frame_origin":"https://example.com","https":true}"#;
        let msg: Inbound = serde_json::from_str(json).unwrap();
        assert_eq!(
            msg,
            Inbound::Query {
                top_origin: "https://example.com".to_string(),
                frame_origin: "https://example.com".to_string(),
                https: true,
            }
        );
    }

    #[test]
    fn unknown_type_maps_to_unknown_variant() {
        let json = r#"{"type":"request_fill","request_id":"abc"}"#;
        let msg: Inbound = serde_json::from_str(json).unwrap();
        assert_eq!(msg, Inbound::Unknown);
    }

    #[test]
    fn query_is_answered_with_available_zero() {
        let reply = handle(Inbound::Query {
            top_origin: "https://example.com".to_string(),
            frame_origin: "https://example.com".to_string(),
            https: true,
        });
        match reply {
            Outbound::Available { count, request_id } => {
                assert_eq!(count, 0);
                // A v4 UUID is 36 chars (hyphenated) and re-parses.
                assert!(Uuid::parse_str(&request_id).is_ok());
            }
            other => panic!("expected Available, got {other:?}"),
        }
    }

    #[test]
    fn unknown_is_answered_with_error() {
        let reply = handle(Inbound::Unknown);
        assert!(matches!(reply, Outbound::Error { .. }));
    }

    #[test]
    fn each_reply_gets_a_distinct_request_id() {
        let a = Outbound::available_none();
        let b = Outbound::available_none();
        let (ra, rb) = match (a, b) {
            (
                Outbound::Available { request_id: ra, .. },
                Outbound::Available { request_id: rb, .. },
            ) => (ra, rb),
            _ => unreachable!(),
        };
        assert_ne!(ra, rb, "request_ids must be freshly minted per reply");
    }

    #[test]
    fn available_serializes_with_type_tag() {
        let json = serde_json::to_value(Outbound::Available {
            request_id: "11111111-1111-4111-8111-111111111111".to_string(),
            count: 0,
        })
        .unwrap();
        assert_eq!(json["type"], "available");
        assert_eq!(json["count"], 0);
        assert_eq!(json["request_id"], "11111111-1111-4111-8111-111111111111");
    }
}
