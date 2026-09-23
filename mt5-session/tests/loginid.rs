//! The loginid client, proved against a mock service on loopback.
//!
//! No real service is contacted. A `TcpListener` on 127.0.0.1 stands in for the
//! loginid endpoint, so the test can assert the two things that matter: that the
//! request is byte-for-byte the documented contract (path, guid, and the
//! `loginidnew5`-prefixed Base64 body for a modern build), and that a decimal
//! reply is parsed into the integer the wrapper expects.

#![cfg(feature = "live")]

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;

use mt5_session::LoginIdService;

/// A one-shot HTTP server that captures the request line + body and replies
/// with `reply`. Returns the base URL and a receiver for what it saw.
fn mock_service(reply: &'static str) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let base = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        if let Ok((mut sock, _)) = listener.accept() {
            // Read the whole request first. Closing the socket with unread
            // inbound bytes sends an RST on Windows, which the client sees as a
            // forced close rather than the reply -- so drain headers, then the
            // Content-Length body, before responding.
            let mut raw = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                let headers_end = raw.windows(4).position(|w| w == b"\r\n\r\n");
                if let Some(end) = headers_end {
                    let header_text = String::from_utf8_lossy(&raw[..end]).to_ascii_lowercase();
                    let want = header_text
                        .split("content-length:")
                        .nth(1)
                        .and_then(|s| s.trim_start().split(|c: char| !c.is_ascii_digit()).next())
                        .and_then(|s| s.parse::<usize>().ok())
                        .unwrap_or(0);
                    if raw.len() >= end + 4 + want {
                        break;
                    }
                }
                match sock.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => raw.extend_from_slice(&chunk[..n]),
                    Err(_) => break,
                }
            }
            let seen = String::from_utf8_lossy(&raw).to_string();
            let body = reply.as_bytes();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = sock.write_all(response.as_bytes());
            let _ = sock.write_all(body);
            let _ = tx.send(seen);
        }
    });
    (base, rx)
}

#[test]
fn modern_f28_request_matches_the_contract_and_parses() {
    let (base, seen) = mock_service("18446744073709551614");
    let service = LoginIdService::new(base, "THE-GUID");

    // Three-byte input; the spec's worked example gives body "loginidnew5AAEC".
    let value = service.resolve_tag(28, &[0x00, 0x01, 0x02], 5830).expect("resolve");
    assert_eq!(value, 18446744073709551614);

    let request = seen.recv().expect("server saw a request");
    assert!(request.starts_with("POST /CheckMT5?guid=THE-GUID "), "path + guid:\n{request}");
    assert!(request.contains("loginidnew5AAEC"), "modern F28 body:\n{request}");
}

#[test]
fn f35_uses_decodeex_without_the_prefix() {
    let (base, seen) = mock_service("42");
    let service = LoginIdService::new(base, "K2");

    let value = service.resolve_tag(35, &[0x00, 0x01, 0x02], 5830).expect("resolve");
    assert_eq!(value, 42);

    let request = seen.recv().expect("server saw a request");
    assert!(request.starts_with("POST /DecodeEx?guid=K2 "), "path + guid:\n{request}");
    // F35 is the plain Base64, no loginidnew5 prefix.
    assert!(request.contains("\r\n\r\nAAEC"), "F35 body is bare Base64:\n{request}");
    assert!(!request.contains("loginidnew5"), "F35 must not carry the prefix");
}

#[test]
fn a_non_numeric_reply_is_an_error_not_a_zero() {
    let (base, _seen) = mock_service("not-a-number");
    let service = LoginIdService::new(base, "K");
    // A wrong number here becomes a silently wrong login id; it must fail loudly.
    assert!(service.resolve_tag(35, &[0x01], 5830).is_err());
}
