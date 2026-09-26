//! Bootstrap addresses plus access points learned from authenticated sync.
use crate::Session;
use mt5_native::{
    error::{ProtocolError, Result},
    sync::AccessPoint,
};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

struct Route {
    address: String,
    learned: bool,
}

pub struct EndpointPool {
    routes: Vec<Route>,
    last_peer: Option<SocketAddr>,
}

fn valid_address(address: &str) -> bool {
    if let Ok(socket) = address.parse::<SocketAddr>() {
        return socket.port() != 0;
    }
    let Some((host, port)) = address.rsplit_once(':') else {
        return false;
    };
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'-'))
        && port.parse::<u16>().is_ok_and(|port| port != 0)
}

fn public_address(address: SocketAddr) -> bool {
    match address.ip() {
        IpAddr::V4(ip) => {
            !(ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_unspecified()
                || ip.is_broadcast()
                || ip.is_multicast())
        }
        IpAddr::V6(ip) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || ip.is_unique_local()
                || ip.is_unicast_link_local())
                && ip.to_ipv4_mapped().is_none_or(|ip| {
                    public_address(SocketAddr::new(IpAddr::V4(ip), address.port()))
                })
        }
    }
}

impl EndpointPool {
    /// Comma-separated host:port or [IPv6]:port bootstrap addresses.
    /// Explicit seeds may be private addresses for local gateways/tests.
    pub fn new(seeds: &str) -> Result<Self> {
        let mut routes = Vec::new();
        for address in seeds.split(',').map(str::trim) {
            if !valid_address(address) {
                return Err(ProtocolError::new("invalid native bootstrap address"));
            }
            if !routes.iter().any(|r: &Route| r.address == address) {
                routes.push(Route {
                    address: address.into(),
                    learned: false,
                });
            }
        }
        if routes.is_empty() || routes.len() > 32 {
            return Err(ProtocolError::new(
                "native bootstrap requires 1..32 addresses",
            ));
        }
        Ok(Self {
            routes,
            last_peer: None,
        })
    }

    pub fn learn(&mut self, points: &[AccessPoint]) {
        for address in points.iter().flat_map(|p| &p.addresses) {
            if self.routes.len() >= 64 {
                break;
            }
            if valid_address(address) && !self.routes.iter().any(|r| r.address == *address) {
                self.routes.push(Route {
                    address: address.clone(),
                    learned: true,
                });
            }
        }
    }

    pub fn addresses(&self) -> impl Iterator<Item = &str> {
        self.routes.iter().map(|r| r.address.as_str())
    }

    pub(crate) fn authenticated(&mut self, peer: SocketAddr) {
        self.last_peer = Some(peer);
    }

    pub fn connect(&mut self) -> Result<Session> {
        let mut targets = Vec::new();
        if let Some(peer) = self.last_peer.take() {
            targets.push(peer);
        }
        for route in &self.routes {
            let Ok(addresses) = route.address.to_socket_addrs() else {
                continue;
            };
            for address in addresses {
                if route.learned && !public_address(address) {
                    continue;
                }
                if targets.len() < 64 && !targets.contains(&address) {
                    targets.push(address);
                }
            }
        }
        // A subsequent reconnect gets a different starting route if all fail.
        self.routes.rotate_left(1);
        Session::connect(targets.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn unavailable_seed_falls_through_and_successful_peer_is_reused() {
        let dead = TcpListener::bind("127.0.0.1:0").unwrap();
        let dead_addr = dead.local_addr().unwrap();
        drop(dead);
        let healthy = TcpListener::bind("127.0.0.1:0").unwrap();
        let healthy_addr = healthy.local_addr().unwrap();
        let mut pool = EndpointPool::new(&format!("{dead_addr},{healthy_addr}")).unwrap();
        let session = pool.connect().unwrap();
        assert_eq!(session.peer_addr().unwrap(), healthy_addr);
        pool.authenticated(session.peer_addr().unwrap());
        drop(session);
        let again = pool.connect().unwrap();
        assert_eq!(again.peer_addr().unwrap(), healthy_addr);
    }

    #[test]
    fn unauthenticated_peer_does_not_pin_reconnects() {
        let first = TcpListener::bind("127.0.0.1:0").unwrap();
        let second = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut pool = EndpointPool::new(&format!(
            "{},{}",
            first.local_addr().unwrap(),
            second.local_addr().unwrap()
        ))
        .unwrap();
        let connection = pool.connect().unwrap();
        assert_eq!(connection.peer_addr().unwrap(), first.local_addr().unwrap());
        drop(connection);
        let connection = pool.connect().unwrap();
        assert_eq!(
            connection.peer_addr().unwrap(),
            second.local_addr().unwrap()
        );
    }

    #[test]
    fn malformed_routes_are_rejected_and_private_advertisements_are_not_dialed() {
        for address in ["", "https://broker:443", "broker:0", "broker:70000"] {
            assert!(EndpointPool::new(address).is_err());
        }
        for address in [
            "10.30.17.85:443",
            "127.0.0.1:701",
            "[::1]:701",
            "[::ffff:10.0.0.1]:443",
        ] {
            assert!(!public_address(address.parse().unwrap()));
        }
        assert!(public_address("15.197.76.41:701".parse().unwrap()));
    }
}
