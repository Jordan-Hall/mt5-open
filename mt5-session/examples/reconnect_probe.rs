//! Read-only fault injection: remove a bootstrap TCP proxy, then reconnect using
//! only access points learned from the broker's native synchronization response.
use mt5_session::{
    LoginProfile,
    client::{Client, Config},
    endpoints::EndpointPool,
};
use std::{
    net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs},
    time::{Duration, Instant},
};

fn quote(client: &mut Client) -> Result<(), Box<dyn std::error::Error>> {
    client.subscribe(&["EURUSD".into()])?;
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(30) {
        client.poll(Duration::from_secs(1))?;
        if client
            .quotes
            .get("EURUSD")
            .is_some_and(|q| q.bid > 0.0 && q.ask > 0.0)
        {
            return Ok(());
        }
    }
    Err("native quote deadline exceeded".into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let upstream = std::env::var("MT5_ADDRESS")?
        .to_socket_addrs()?
        .next()
        .ok_or("missing upstream")?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let seed = listener.local_addr()?.to_string();
    let proxy = std::thread::spawn(move || -> std::io::Result<()> {
        let (mut local, _) = listener.accept()?;
        drop(listener);
        let mut broker = TcpStream::connect_timeout(&upstream, Duration::from_secs(15))?;
        local.set_read_timeout(Some(Duration::from_secs(30)))?;
        broker.set_read_timeout(Some(Duration::from_secs(30)))?;
        let mut local_writer = local.try_clone()?;
        let mut broker_reader = broker.try_clone()?;
        let outbound = std::thread::spawn(move || {
            let _ = std::io::copy(&mut local, &mut broker);
            let _ = broker.shutdown(Shutdown::Both);
        });
        let _ = std::io::copy(&mut broker_reader, &mut local_writer);
        let _ = local_writer.shutdown(Shutdown::Both);
        let _ = outbound.join();
        Ok(())
    });
    let profile = LoginProfile::from_json(&std::fs::read_to_string(std::env::var(
        "MT5_LOGIN_PROFILE",
    )?)?)?;
    let config = Config {
        address: seed.clone(),
        login: std::env::var("MT5_LOGIN")?.parse()?,
        password: std::env::var("MT5_PASSWORD")?,
        client_build: profile.client_build,
        profile,
    };
    let mut endpoints = EndpointPool::new(&seed)?;
    let mut client = Client::connect_with_endpoints(&config, &mut endpoints)?;
    quote(&mut client)?;
    println!(
        "bootstrap synchronized; advertised routes={}",
        endpoints.addresses().count() - 1
    );
    drop(client);
    proxy.join().map_err(|_| "proxy worker failed")??;
    let start = Instant::now();
    let mut client = Client::connect_with_endpoints(&config, &mut endpoints)?;
    if client.peer_addr()?.ip().is_loopback() {
        return Err("reconnect used the removed proxy".into());
    }
    quote(&mut client)?;
    println!(
        "PASS: removed bootstrap, reauthenticated through broker advertisement, identity and quotes verified in {:.2}s",
        start.elapsed().as_secs_f64()
    );
    Ok(())
}
