//! D.4.1 task-2 integration test: drive the host's read→dispatch→write loop
//! over an in-memory pipe (a `Cursor`) and assert the observable frames.
//!
//! No browser, no network, no crypto — this is the CI-gated proof of the
//! `query → available{count:0}` round trip and the unknown-type → `error`
//! behavior the manual browser smoke (task 4) mirrors.

use std::io::Cursor;

use secretary_browser_host::frame;
use secretary_browser_host::protocol::Outbound;

/// Serialize a sequence of inbound messages into a single framed byte stream,
/// exactly as the extension would write to the host's stdin.
fn framed_input(messages: &[serde_json::Value]) -> Vec<u8> {
    let mut buf = Vec::new();
    for m in messages {
        frame::encode(&mut buf, m).expect("encode test input frame");
    }
    buf
}

/// Decode every frame the host wrote to its stdout.
fn drain_output(bytes: Vec<u8>) -> Vec<Outbound> {
    let mut cursor = Cursor::new(bytes);
    let mut out = Vec::new();
    while let Some(msg) = frame::decode::<Outbound, _>(&mut cursor).expect("decode host output") {
        out.push(msg);
    }
    out
}

#[test]
fn query_round_trips_to_available_zero() {
    let input = framed_input(&[serde_json::json!({
        "type": "query",
        "top_origin": "https://example.com",
        "frame_origin": "https://example.com",
        "https": true,
    })]);

    let mut reader = Cursor::new(input);
    let mut writer = Vec::new();
    secretary_browser_host::run(&mut reader, &mut writer).expect("loop runs to clean EOF");

    let replies = drain_output(writer);
    assert_eq!(replies.len(), 1, "exactly one reply for one query");
    match &replies[0] {
        Outbound::Available { count, request_id } => {
            assert_eq!(*count, 0);
            assert_eq!(request_id.len(), 36, "hyphenated v4 UUID");
        }
        other => panic!("expected Available, got {other:?}"),
    }
}

#[test]
fn unknown_type_is_answered_with_error() {
    let input = framed_input(&[serde_json::json!({
        "type": "request_fill",
        "request_id": "whatever",
    })]);

    let mut reader = Cursor::new(input);
    let mut writer = Vec::new();
    secretary_browser_host::run(&mut reader, &mut writer).expect("loop runs to clean EOF");

    let replies = drain_output(writer);
    assert_eq!(replies.len(), 1);
    assert!(matches!(replies[0], Outbound::Error { .. }));
}

#[test]
fn multiple_queries_each_get_a_reply() {
    let q = serde_json::json!({
        "type": "query",
        "top_origin": "https://a.example",
        "frame_origin": "https://a.example",
        "https": true,
    });
    let input = framed_input(&[q.clone(), q.clone(), q]);

    let mut reader = Cursor::new(input);
    let mut writer = Vec::new();
    secretary_browser_host::run(&mut reader, &mut writer).expect("loop runs to clean EOF");

    let replies = drain_output(writer);
    assert_eq!(replies.len(), 3);
    assert!(replies
        .iter()
        .all(|r| matches!(r, Outbound::Available { count: 0, .. })));

    // request_ids are minted fresh per reply.
    let ids: std::collections::HashSet<&str> = replies
        .iter()
        .map(|r| match r {
            Outbound::Available { request_id, .. } => request_id.as_str(),
            Outbound::Error { request_id, .. } => request_id.as_str(),
        })
        .collect();
    assert_eq!(ids.len(), 3, "each reply has a distinct request_id");
}

#[test]
fn empty_stdin_is_a_clean_shutdown() {
    let mut reader = Cursor::new(Vec::<u8>::new());
    let mut writer = Vec::new();
    secretary_browser_host::run(&mut reader, &mut writer).expect("clean EOF is not an error");
    assert!(writer.is_empty(), "no input → no output");
}

#[test]
fn malformed_json_body_yields_error_then_keeps_serving() {
    // A valid frame whose body is not valid JSON, followed by a good query.
    // The host must answer the bad frame with an error and still serve the next.
    let mut input = Vec::new();
    let bad_body = b"{not json";
    input.extend_from_slice(&(bad_body.len() as u32).to_ne_bytes());
    input.extend_from_slice(bad_body);
    frame::encode(
        &mut input,
        &serde_json::json!({
            "type": "query",
            "top_origin": "https://b.example",
            "frame_origin": "https://b.example",
            "https": true,
        }),
    )
    .unwrap();

    let mut reader = Cursor::new(input);
    let mut writer = Vec::new();
    secretary_browser_host::run(&mut reader, &mut writer).expect("loop survives a bad frame");

    let replies = drain_output(writer);
    assert_eq!(replies.len(), 2, "an error then an available");
    assert!(matches!(replies[0], Outbound::Error { .. }));
    assert!(matches!(replies[1], Outbound::Available { count: 0, .. }));
}
