//! What the socket does, proved against a server that runs on loopback.
//!
//! None of this reaches a broker. A `TcpListener` on 127.0.0.1 is enough to
//! test the three things that actually go wrong in a framed link: that a frame
//! survives the round trip, that two frames arriving in one read are both
//! recovered, and that a connection dying mid-frame is reported rather than
//! passed off as a message.

#![cfg(feature = "live")]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use mt5_native::frame::Frame;
use mt5_session::Session;

/// A listener that hands the test the address and the accepted socket.
fn server() -> (String, std::sync::mpsc::Receiver<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let address = listener.local_addr().expect("addr").to_string();
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        if let Ok((socket, _)) = listener.accept() {
            let _ = tx.send(socket);
        }
    });
    (address, rx)
}

#[test]
fn a_frame_survives_the_round_trip() {
    let (address, accepted) = server();
    let mut session = Session::connect(address).expect("connect");
    let mut peer = accepted.recv().expect("accept");

    let sent = Frame::new(0, 1, 0, b"hello there".to_vec());
    session.send(&sent).expect("send");

    let mut buffer = vec![0u8; 1024];
    let read = peer.read(&mut buffer).expect("server read");
    assert_eq!(&buffer[..read], &sent.pack()[..], "the bytes on the wire are the packed frame");
}

#[test]
fn two_frames_in_one_read_are_both_recovered() {
    // The wire has no idea where our messages begin. A server is free to put
    // two frames in one packet and the parser has to find both, or the second
    // one is silently lost -- which for a quote stream means a price that
    // never arrives.
    let (address, accepted) = server();
    let mut session = Session::connect(address).expect("connect");
    let mut peer = accepted.recv().expect("accept");

    let first = Frame::new(0, 1, 0, b"one".to_vec());
    let second = Frame::new(0, 2, 0, b"two".to_vec());
    let mut both = first.pack();
    both.extend_from_slice(&second.pack());
    peer.write_all(&both).expect("server write");
    peer.flush().expect("flush");

    let a = session.next_frame().expect("first frame");
    let b = session.next_frame().expect("second frame");
    assert_eq!(a.payload, b"one");
    assert_eq!(b.payload, b"two");
}

#[test]
fn a_connection_dying_mid_frame_is_an_error_not_a_message() {
    // Half a frame is not a message. Accepting one is how a parser starts
    // reporting fields that were never sent.
    let (address, accepted) = server();
    let mut session = Session::connect(address).expect("connect");
    let mut peer = accepted.recv().expect("accept");

    let whole = Frame::new(0, 1, 0, b"a payload long enough to cut".to_vec()).pack();
    peer.write_all(&whole[..whole.len() / 2]).expect("half a frame");
    peer.flush().expect("flush");
    drop(peer);

    let outcome = session.next_frame();
    assert!(outcome.is_err(), "a truncated frame must not be handed out as a message");
}

#[test]
fn connecting_somewhere_closed_fails_rather_than_hanging() {
    // Bind and drop, so the port is almost certainly refusing.
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let address = listener.local_addr().expect("addr").to_string();
    drop(listener);
    assert!(Session::connect(address).is_err());
}
