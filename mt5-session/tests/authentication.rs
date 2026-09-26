#![cfg(feature = "live")]

use mt5_native::account::ACCOUNT_REC_SIZE;
use mt5_native::cipher::{SessionCipher, startup_encrypt_default};
use mt5_native::compression::make_compressed_payload;
use mt5_native::frame::{COMPRESSED, FINAL, Frame};
use mt5_native::keys::derive_session_key;
use mt5_native::tlv::encode_tlvs;
use mt5_session::{LoginProfile, Session};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

const LOGIN: u64 = 12345;
const PASSWORD: &str = "SyntheticPassword";

const SERVER: &str = "SyntheticBroker-Demo";

fn profile() -> LoginProfile {
    profile_with_access(LOGIN, false, SERVER)
}

fn profile_with_access(login: u64, read_only: bool, server: &str) -> LoginProfile {
    LoginProfile::from_json(
        &serde_json::json!({
            "client_build":6182,"server_build":5830,"environment":"file=test-client\t",
            "account":{"login":login,"mode":"demo","read_only":read_only,"server":server}
        })
        .to_string(),
    )
    .unwrap()
}

fn program(words: &[u64]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

fn frame(socket: &mut TcpStream) -> Frame {
    let mut head = [0; 9];
    socket.read_exact(&mut head).unwrap();
    let size = i32::from_le_bytes(head[1..5].try_into().unwrap()) as usize;
    assert!(size < 8192);
    let mut body = vec![0; size];
    socket.read_exact(&mut body).unwrap();
    Frame::new(
        head[0],
        u16::from_le_bytes(head[5..7].try_into().unwrap()),
        u16::from_le_bytes(head[7..9].try_into().unwrap()),
        body,
    )
}

fn server(
    status: i32,
    returned_login: u64,
    wrong_sequence: bool,
) -> (String, thread::JoinHandle<()>) {
    server_exchange(status, returned_login, wrong_sequence, false, None)
}

fn server_exchange(
    status: i32,
    returned_login: u64,
    wrong_sequence: bool,
    subscription: bool,
    update: Option<(u64, i32)>,
) -> (String, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let worker = thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        let hello = frame(&mut socket);
        assert_eq!(hello.command, 0);
        let mut challenge = vec![0; 32];
        challenge[8..24].copy_from_slice(&[3; 16]);
        socket
            .write_all(
                &Frame::new(
                    0,
                    hello.sequence,
                    FINAL,
                    startup_encrypt_default(&challenge),
                )
                .pack(),
            )
            .unwrap();
        let auth = frame(&mut socket);
        assert_eq!(auth.command, 1);
        let mut result = vec![0; 44];
        result[24..26].copy_from_slice(&5830i16.to_le_bytes());
        result[26..28].copy_from_slice(&5830i16.to_le_bytes());
        result.extend(encode_tlvs(&[
            (7, vec![0; 16]),
            (
                0,
                SERVER.encode_utf16().flat_map(u16::to_le_bytes).collect(),
            ),
            (28, program(&[113 << 11, 123, 456, 106 << 11, 0, 0])),
            (35, program(&[127 << 17, 654, 321, 114 << 17, 0, 0])),
        ]));
        socket
            .write_all(
                &Frame::new(1, auth.sequence, FINAL, startup_encrypt_default(&result)).pack(),
            )
            .unwrap();
        let sync = frame(&mut socket);
        assert_eq!(sync.command, 12);
        let key = derive_session_key(LOGIN, PASSWORD, &[0; 16]).unwrap();
        let mut rx = SessionCipher::new(&key).unwrap();
        let request = rx.decrypt(&sync.payload);
        let request_tags = mt5_native::tlv::parse_tlvs(&request).unwrap();
        let values = mt5_native::login::login_value_wrapper(
            LOGIN,
            6182,
            5830,
            &[3; 16],
            579 ^ mt5_native::challenge::LOGIN_SEED ^ 0xc9d140050011,
            975 ^ mt5_native::challenge::LOGIN_SEED ^ 0xc9d140050011,
        );
        for (tag, expected) in [(88, values.tag88_value), (134, values.tag134_value)] {
            assert_eq!(
                request_tags.iter().find(|(t, _)| *t == tag).unwrap().1,
                expected
            );
        }
        let mut payload = status.to_le_bytes().to_vec();
        if status == 0 {
            payload.push(37);
            let mut account = vec![0; ACCOUNT_REC_SIZE];
            account[..8].copy_from_slice(&returned_login.to_le_bytes());
            account[1836..1844].copy_from_slice(&812.5f64.to_le_bytes());
            payload.extend(account);
        }
        let mut tx = SessionCipher::new(&key).unwrap();
        let seq = sync.sequence + u16::from(wrong_sequence);
        let first = tx.encrypt(&make_compressed_payload(&payload[..2]).unwrap());
        let last = tx.encrypt(&make_compressed_payload(&payload[2..]).unwrap());
        let mut wire = Frame::new(12, seq, COMPRESSED, first).pack();
        wire.extend(Frame::new(10, 0, FINAL, vec![]).pack());
        wire.extend(Frame::new(12, seq, COMPRESSED | FINAL, last).pack());
        wire.extend(
            Frame::new(
                50,
                77,
                COMPRESSED | FINAL,
                tx.encrypt(&make_compressed_payload(b"next-message").unwrap()),
            )
            .pack(),
        );
        if let Some((login, flags)) = update {
            let mut body = vec![19];
            body.extend(1i32.to_le_bytes());
            body.extend([0; 216]);
            let mut account = vec![0; ACCOUNT_REC_SIZE];
            account[..8].copy_from_slice(&login.to_le_bytes());
            account[456..460].copy_from_slice(&flags.to_le_bytes());
            body.extend(account);
            wire.extend(Frame::new(55, 79, FINAL, tx.encrypt(&body)).pack());
        }
        socket.write_all(&wire).unwrap();
        if update.is_some() {
            let mut byte = [0];
            assert_eq!(
                socket.read(&mut byte).unwrap(),
                0,
                "client sent after account restriction"
            );
        }
        if subscription {
            let request = frame(&mut socket);
            assert_eq!(request.command, 105);
            assert_eq!(
                rx.decrypt(&request.payload),
                mt5_native::subscription::make_subscription_payload(&[1, 51])
            );
            socket
                .write_all(&Frame::new(50, 78, FINAL, tx.encrypt(b"after-subscribe")).pack())
                .unwrap();
        }
    });
    (address, worker)
}

#[test]
fn read_only_profile_rejects_mutations_without_sending_or_advancing_cipher() {
    let (address, worker) = server_exchange(0, LOGIN, false, true, None);
    let mut session = Session::connect(address).unwrap();
    session.authenticate(LOGIN, PASSWORD, 6182).unwrap();
    session
        .synchronize(&profile_with_access(LOGIN, true, SERVER))
        .unwrap();
    assert_eq!(session.next_message().unwrap().payload, b"next-message");
    assert!(
        session
            .send_trade(&[0; 800])
            .unwrap_err()
            .to_string()
            .contains("read-only")
    );
    for command in [107, 108, 255] {
        assert!(
            session
                .send_request(command, &[0; 8])
                .unwrap_err()
                .to_string()
                .contains("read-only")
        );
    }
    // The server expects the next wire frame to be this subscription and decrypts it.
    session.subscribe(&[1, 51]).unwrap();
    assert_eq!(session.next_message().unwrap().payload, b"after-subscribe");
    worker.join().unwrap();
}

#[test]
fn idle_poll_preserves_both_ciphers_for_subscription_and_next_quote() {
    let (address, worker) = server_exchange(0, LOGIN, false, true, None);
    let mut session = Session::connect(address).unwrap();
    session.authenticate(LOGIN, PASSWORD, 6182).unwrap();
    session.synchronize(&profile()).unwrap();
    assert_eq!(session.next_message().unwrap().payload, b"next-message");
    assert!(
        session
            .poll_message(std::time::Duration::from_millis(20))
            .unwrap()
            .is_none()
    );
    assert_eq!(session.account().unwrap().balance, 812.5);
    session.subscribe(&[1, 51]).unwrap();
    assert_eq!(session.next_message().unwrap().payload, b"after-subscribe");
    worker.join().unwrap();
}

#[test]
fn compressed_fragments_produce_verified_account_and_preserve_cipher() {
    let (address, worker) = server(0, LOGIN, false);
    let mut session = Session::connect(address).unwrap();
    assert!(session.account().is_err());
    session.authenticate(LOGIN, PASSWORD, 6182).unwrap();
    assert!(session.account().is_err());
    assert!(
        session
            .synchronize(&profile_with_access(LOGIN + 1, false, SERVER))
            .err()
            .unwrap()
            .to_string()
            .contains("different account")
    );
    // The same numeric login on another server is a different account.
    assert!(
        session
            .synchronize(&profile_with_access(LOGIN, false, "AnotherBroker-Demo"))
            .is_err()
    );
    let sync = session.synchronize(&profile()).unwrap();
    assert_eq!(sync.account.login, LOGIN);
    assert_eq!(sync.account.balance, 812.5);
    assert_eq!(session.account().unwrap(), sync.account);
    assert_eq!(session.next_message().unwrap().payload, b"next-message");
    assert!(session.authenticate(LOGIN, PASSWORD, 6182).is_err());
    assert!(session.synchronize(&profile()).is_err());
    worker.join().unwrap();
    assert!(session.next_message().is_err());
    assert!(session.account().is_err());
}

#[test]
fn rejected_status_wrong_identity_and_wrong_sequence_never_become_ready() {
    for (status, login, wrong_sequence) in
        [(5, LOGIN, false), (0, LOGIN + 1, false), (0, LOGIN, true)]
    {
        let (address, worker) = server(status, login, wrong_sequence);
        let mut session = Session::connect(address).unwrap();
        session.authenticate(LOGIN, PASSWORD, 6182).unwrap();
        assert!(session.synchronize(&profile()).is_err());
        assert!(session.account().is_err());
        assert!(session.authenticate(LOGIN, PASSWORD, 6182).is_err());
        worker.join().unwrap();
    }
}

#[test]
fn malformed_profiles_are_rejected_without_echoing_their_contents() {
    for input in [
        "secret-invalid-json",
        r#"{"client_build":6182,"server_build":5830}"#,
    ] {
        let error = LoginProfile::from_json(input).unwrap_err();
        assert!(!error.to_string().contains(input));
    }
    assert!(!format!("{:?}", profile()).contains("file=test-client"));
}

#[test]
fn account_profiles_are_isolated_before_connecting() {
    use mt5_session::client::{Client, Config};
    let profile = profile();
    assert_eq!(profile.account_mode(LOGIN).unwrap(), "demo");
    let result = Client::connect(&Config {
        address: "not-a-socket-address".into(),
        login: LOGIN + 1,
        password: PASSWORD.into(),
        client_build: 6182,
        profile,
    });
    assert!(
        result
            .err()
            .unwrap()
            .to_string()
            .contains("different account")
    );
}

#[test]
fn foreign_account_update_invalidates_session_before_another_request() {
    let (address, worker) = server_exchange(0, LOGIN, false, false, Some((LOGIN + 1, 0)));
    let mut session = Session::connect(address).unwrap();
    session.authenticate(LOGIN, PASSWORD, 6182).unwrap();
    session.synchronize(&profile()).unwrap();
    session.next_message().unwrap();
    assert!(
        session
            .next_message()
            .unwrap_err()
            .to_string()
            .contains("authenticated login")
    );
    assert!(session.account().is_err());
    assert!(session.send_request(105, &[0; 8]).is_err());
    assert!(session.send_trade(&[0; 800]).is_err());
    drop(session);
    worker.join().unwrap();
}

#[test]
fn read_only_account_update_blocks_mutations_before_sending() {
    let (address, worker) = server_exchange(0, LOGIN, false, false, Some((LOGIN, 8)));
    let mut session = Session::connect(address).unwrap();
    session.authenticate(LOGIN, PASSWORD, 6182).unwrap();
    session.synchronize(&profile()).unwrap();
    session.next_message().unwrap();
    session.next_message().unwrap();
    assert!(session.is_read_only().unwrap());
    assert!(session.account().unwrap().is_read_only());
    assert!(session.send_request(107, &[0; 8]).is_err());
    assert!(session.send_trade(&[0; 800]).is_err());
    drop(session);
    worker.join().unwrap();
}

#[test]
fn invalid_client_state_cannot_submit_another_trade() {
    use mt5_session::client::{Client, Config};
    let (address, worker) = server_exchange(0, LOGIN, false, false, Some((LOGIN, 0)));
    let mut client = Client::connect(&Config {
        address,
        login: LOGIN,
        password: PASSWORD.into(),
        client_build: 6182,
        profile: profile(),
    })
    .unwrap();
    // The fake broker's next-message bytes are deliberately not a valid quote.
    assert!(client.poll(std::time::Duration::from_secs(1)).is_err());
    let mut trade = vec![0; 800];
    trade[..4].copy_from_slice(&1i32.to_le_bytes());
    assert!(
        client
            .trade(&trade)
            .err()
            .unwrap()
            .to_string()
            .contains("fresh synchronization")
    );
    drop(client);
    worker.join().unwrap();
}
