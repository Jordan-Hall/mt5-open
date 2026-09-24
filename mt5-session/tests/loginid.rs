#![cfg(feature = "live")]

use mt5_native::cipher::{SessionCipher, startup_decrypt_default, startup_encrypt_default};
use mt5_native::compression::make_compressed_payload;
use mt5_native::frame::{COMPRESSED, FINAL, Frame, FrameParser};
use mt5_native::keys::derive_session_key;
use mt5_native::login::login_value_wrapper;
use mt5_native::tlv::{encode_tlvs, parse_tlvs};
use mt5_session::{LoginContext, LoginDerivation, Session, UnsupportedLoginProfile};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

const LOGIN: u64 = 12345678;
const PASSWORD: &str = "ExamplePassword";
const CHALLENGE: [u8; 16] = [3; 16];

fn read_frame(socket: &mut TcpStream) -> Frame {
    let mut header = [0u8; 9];
    socket.read_exact(&mut header).unwrap();
    let size = i32::from_le_bytes(header[1..5].try_into().unwrap());
    assert!((0..65536).contains(&size));
    let mut bytes = header.to_vec();
    bytes.resize(9 + size as usize, 0);
    socket.read_exact(&mut bytes[9..]).unwrap();
    FrameParser::default().feed(&bytes).unwrap().remove(0)
}

fn write_frame(socket: &mut TcpStream, command: u8, sequence: u16, payload: &[u8]) {
    socket
        .write_all(&Frame::new(command, sequence, FINAL, startup_encrypt_default(payload)).pack())
        .unwrap();
}

fn peer<F>(serve: F) -> (String, thread::JoinHandle<()>)
where
    F: FnOnce(TcpStream) + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let handle = thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        serve(socket);
    });
    (address, handle)
}

fn authenticate_peer(socket: &mut TcpStream, status: i32, otp: bool) {
    let hello = read_frame(socket);
    assert_eq!(hello.command, 0);
    let mut challenge = [0u8; 32];
    challenge[8..24].copy_from_slice(&CHALLENGE);
    write_frame(socket, 0, hello.sequence, &challenge);
    let auth = read_frame(socket);
    assert_eq!(auth.command, 1);
    let plaintext = startup_decrypt_default(&auth.payload);
    let tags = parse_tlvs(&plaintext[34..]).unwrap();
    assert_eq!(tags.iter().any(|(tag, _)| *tag == 18), otp);
    let mut result = vec![0u8; 44];
    result[4..8].copy_from_slice(&status.to_le_bytes());
    result[24..26].copy_from_slice(&5500i16.to_le_bytes());
    result[26..28].copy_from_slice(&5499i16.to_le_bytes());
    result.extend(encode_tlvs(&[
        (7, vec![0]),
        (28, vec![1, 2]),
        (35, vec![3, 4]),
    ]));
    write_frame(socket, 1, auth.sequence, &result);
}

fn fixture_resolver(context: &LoginContext<'_>) -> mt5_native::Result<LoginDerivation> {
    assert_eq!(context.login, LOGIN);
    assert_eq!(
        (
            context.client_build,
            context.server_build,
            context.record_build
        ),
        (5500, 5500, 5499)
    );
    assert_eq!(context.server_challenge, &CHALLENGE);
    assert_eq!(context.input(28)?, [1, 2]);
    assert_eq!(context.input(35)?, [3, 4]);
    // Synthetic outputs exercise the wrapper, not the unknown inner mappings.
    Ok(LoginDerivation { f28: 17, f35: 23 })
}

#[test]
fn normal_authentication_exposes_login_challenge_and_local_wrapper() {
    let (address, handle) = peer(|mut socket| authenticate_peer(&mut socket, 0, false));
    let mut session = Session::connect(address).unwrap();
    session.authenticate(LOGIN, PASSWORD, 5500).unwrap();
    assert!(session.certificate_challenge().is_err());
    let values = session.resolve_login_values(&fixture_resolver).unwrap();
    assert_eq!(
        values,
        login_value_wrapper(LOGIN, 5500, 5500, &CHALLENGE, 17, 23)
    );
    assert!(session.authenticate(LOGIN, PASSWORD, 5500).is_err());
    handle.join().unwrap();
}

#[test]
fn unsupported_derivation_does_not_send_a_sync_frame() {
    let (address, handle) = peer(|mut socket| {
        authenticate_peer(&mut socket, 0, false);
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        let mut byte = [0u8; 1];
        let error = socket.read(&mut byte).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
    });
    let mut session = Session::connect(address).unwrap();
    session.authenticate(LOGIN, PASSWORD, 5500).unwrap();
    assert!(session.synchronize_with(&UnsupportedLoginProfile).is_err());
    handle.join().unwrap();
}

#[test]
fn rejected_authentication_retains_only_structural_diagnostics() {
    let (address, handle) = peer(|mut socket| authenticate_peer(&mut socket, 1001, false));
    let mut session = Session::connect(address).unwrap();
    assert!(session.authenticate(LOGIN, PASSWORD, 5500).is_err());
    assert_eq!(session.auth_summary().unwrap().status, 1001);
    assert!(session.login_context().is_err());
    assert!(session.authenticate(LOGIN, PASSWORD, 5500).is_err());
    handle.join().unwrap();
}

#[test]
fn unexpected_challenge_command_or_sequence_is_rejected_before_password_response() {
    for (command, sequence) in [(1, 1), (0, 99)] {
        let (address, handle) = peer(move |mut socket| {
            read_frame(&mut socket);
            write_frame(&mut socket, command, sequence, &[0; 32]);
            let mut byte = [0u8; 1];
            assert_eq!(socket.read(&mut byte).unwrap(), 0);
        });
        let mut session = Session::connect(address).unwrap();
        assert!(session.authenticate(LOGIN, PASSWORD, 5500).is_err());
        handle.join().unwrap();
    }
}

#[test]
fn otp_and_certificate_continuation_keep_the_outgoing_cipher_position() {
    let (address, handle) = peer(|mut socket| {
        authenticate_peer(&mut socket, 1003, true);
        let mut cipher =
            SessionCipher::new(&derive_session_key(LOGIN, PASSWORD, &[0]).unwrap()).unwrap();
        let certificate = read_frame(&mut socket);
        assert_eq!(certificate.command, 2);
        let body = cipher.decrypt(&certificate.payload);
        let tags = parse_tlvs(&body[16..]).unwrap();
        assert_eq!(tags, vec![(4, vec![3, 2, 1]), (3, vec![9])]);
        let sync = read_frame(&mut socket);
        assert_eq!(sync.command, 12);
        assert!(
            parse_tlvs(&cipher.decrypt(&sync.payload))
                .unwrap()
                .iter()
                .any(|(tag, _)| *tag == 88)
        );
        let mut tx =
            SessionCipher::new(&derive_session_key(LOGIN, PASSWORD, &[0]).unwrap()).unwrap();
        socket
            .write_all(
                &Frame::new(12, sync.sequence, FINAL, tx.encrypt(&0i32.to_le_bytes())).pack(),
            )
            .unwrap();
    });
    let mut session = Session::connect(address).unwrap();
    assert!(
        session
            .authenticate_with_otp(LOGIN, PASSWORD, 5500, Some("123456"))
            .unwrap()
            .certificate_required
    );
    assert_eq!(session.certificate_challenge().unwrap(), &CHALLENGE);
    assert!(session.resolve_login_values(&fixture_resolver).is_err());
    assert!(session.certificate_continuation(&[], &[9]).is_err());
    session.certificate_continuation(&[1, 2, 3], &[9]).unwrap();
    assert_eq!(session.synchronize_with(&fixture_resolver).unwrap().0, 0);
    handle.join().unwrap();
}

#[test]
fn compressed_fragmented_sync_keeps_interleaved_account_update_and_cipher_alignment() {
    let (address, handle) = peer(|mut socket| {
        authenticate_peer(&mut socket, 0, false);
        let request = read_frame(&mut socket);
        let key = derive_session_key(LOGIN, PASSWORD, &[0]).unwrap();
        let mut tx = SessionCipher::new(&key).unwrap();
        let first = make_compressed_payload(&[0, 0]).unwrap();
        let mut wire = Frame::new(12, request.sequence, COMPRESSED, tx.encrypt(&first)).pack();
        let mut update = vec![19];
        update.extend_from_slice(&1i32.to_le_bytes());
        update.extend_from_slice(&[0; 216]);
        let mut record = vec![0; 2996];
        record[..8].copy_from_slice(&LOGIN.to_le_bytes());
        record[1836..1844].copy_from_slice(&123.5f64.to_le_bytes());
        update.extend(record);
        wire.extend(
            Frame::new(
                55,
                77,
                FINAL | COMPRESSED,
                tx.encrypt(&make_compressed_payload(&update).unwrap()),
            )
            .pack(),
        );
        wire.extend(Frame::new(12, request.sequence, FINAL, tx.encrypt(&[0, 0, 42])).pack());
        for chunk in wire.chunks(13) {
            socket.write_all(chunk).unwrap();
        }
    });
    let mut session = Session::connect(address).unwrap();
    session.authenticate(LOGIN, PASSWORD, 5500).unwrap();
    assert_eq!(
        session.synchronize_with(&fixture_resolver).unwrap(),
        (0, vec![0, 0, 0, 0, 42])
    );
    let state = session.read_account_state().unwrap();
    assert_eq!((state.login, state.balance), (LOGIN, 123.5));
    handle.join().unwrap();
}

#[test]
fn nonzero_sync_status_closes_the_session() {
    let (address, handle) = peer(|mut socket| {
        authenticate_peer(&mut socket, 0, false);
        let request = read_frame(&mut socket);
        let mut tx =
            SessionCipher::new(&derive_session_key(LOGIN, PASSWORD, &[0]).unwrap()).unwrap();
        socket
            .write_all(
                &Frame::new(12, request.sequence, FINAL, tx.encrypt(&5i32.to_le_bytes())).pack(),
            )
            .unwrap();
    });
    let mut session = Session::connect(address).unwrap();
    session.authenticate(LOGIN, PASSWORD, 5500).unwrap();
    assert!(session.synchronize_with(&fixture_resolver).is_err());
    assert!(session.read_account_state().is_err());
    handle.join().unwrap();
}

#[test]
fn context_redacts_material_and_rejects_ambiguous_inputs() {
    let tags = vec![
        (28, b"private-material".to_vec()),
        (35, vec![]),
        (28, vec![1]),
    ];
    let context = LoginContext {
        login: LOGIN,
        client_build: 5500,
        server_build: 5500,
        record_build: 5499,
        server_challenge: &CHALLENGE,
        tags: &tags,
    };
    assert!(context.input(28).is_err());
    assert!(context.input(35).is_err());
    assert!(context.input(7).is_err());
    let debug = format!("{context:?}");
    assert!(!debug.contains("private-material"));
    assert!(!debug.contains(&LOGIN.to_string()));
}
