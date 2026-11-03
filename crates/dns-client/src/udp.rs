use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::ClientError;

/// Idle sockets retained per upstream server. The pool bounds both memory
/// and the source-port set a server sees from this resolver.
const MAX_IDLE_PER_SERVER: usize = 16;

type SocketPool = Arc<Mutex<HashMap<SocketAddr, Vec<UdpSocket>>>>;

/// UDP transport for upstream DNS queries.
///
/// Successful exchanges park their connected socket in a per-server pool so
/// the next query to the same server reuses it instead of paying a fresh
/// `socket`/`bind`/`connect`/`close` cycle. A pooled socket stays connected
/// to one server, so the kernel still drops datagrams from any other source
/// address.
///
/// Because source ports are now reused, spoofing resistance relies on the
/// resolver's per-query defenses rather than port entropy alone: 0x20 case
/// randomization (`case_randomization`, on by default) and DNS COOKIEs
/// (`cookies`, on by default), both of which an attacker must guess
/// alongside the transaction ID. The receive loop additionally discards
/// datagrams that do not echo the query's transaction ID, so a stale reply
/// left over from an earlier exchange cannot be mistaken for this answer.
/// A timed-out or failed exchange drops its socket instead of returning it
/// to the pool, so a late reply has nowhere to land.
#[derive(Clone, Debug, Default)]
pub struct UdpClient {
    bind_addr: Option<IpAddr>,
    pool: SocketPool,
}

impl UdpClient {
    /// Create a client, optionally binding outgoing sockets to `bind_addr`.
    pub fn new(bind_addr: Option<SocketAddr>) -> std::io::Result<Self> {
        Ok(Self {
            bind_addr: bind_addr.map(|addr| addr.ip()),
            pool: SocketPool::default(),
        })
    }

    fn local_addr(&self, server: SocketAddr) -> SocketAddr {
        let bind = self.bind_addr.unwrap_or(match server {
            SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        });
        SocketAddr::new(bind, 0)
    }

    /// Send `query` to `server` and wait up to `dur` for a response.
    ///
    /// Reuses an idle pooled socket for `server` when one exists, otherwise
    /// binds and connects a fresh one. The socket returns to the pool only
    /// after a response carrying the query's transaction ID arrives; on
    /// timeout or I/O error it is dropped so a late reply cannot be read by
    /// a later query.
    ///
    /// # Arguments
    ///
    /// * `server` - Upstream server address
    /// * `query` - DNS wire-format query; its first two bytes are the
    ///   transaction ID echoed by the response
    /// * `dur` - Budget for the whole exchange, including skipped datagrams
    ///
    /// # Returns
    ///
    /// The response datagram, truncated to the bytes received
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Timeout`] when no matching response arrives
    /// within `dur`, and [`ClientError::Io`] on send or receive failures
    pub async fn send_recv(
        &self,
        server: SocketAddr,
        query: &[u8],
        dur: Duration,
    ) -> Result<Vec<u8>, ClientError> {
        let socket = match self.take(server) {
            Some(socket) => socket,
            None => self.connect(server).await?,
        };
        socket.send(query).await?;

        // EDNS can advertise up to 65535 bytes, so do not cap the read buffer.
        let mut buf = vec![0u8; 65_535];
        let received = timeout(dur, async {
            loop {
                let len = socket.recv(&mut buf).await?;
                // Skip stale datagrams left over from an earlier exchange on
                // this pooled socket. `len >= 2` ensures the compared bytes
                // were actually received rather than zero-fill.
                if len >= 2 && query.len() >= 2 && buf[..2] == query[..2] {
                    return Ok(len);
                }
            }
        })
        .await;

        match received {
            Ok(Ok(len)) => {
                buf.truncate(len);
                self.put(server, socket);
                Ok(buf)
            }
            Ok(Err(error)) => Err(ClientError::Io(error)),
            Err(_) => Err(ClientError::Timeout),
        }
    }

    async fn connect(&self, server: SocketAddr) -> Result<UdpSocket, ClientError> {
        let socket = UdpSocket::bind(self.local_addr(server)).await?;
        socket.connect(server).await?;
        Ok(socket)
    }

    fn take(&self, server: SocketAddr) -> Option<UdpSocket> {
        self.pool
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_mut(&server)
            .and_then(Vec::pop)
    }

    fn put(&self, server: SocketAddr, socket: UdpSocket) {
        let mut pool = self.pool.lock().unwrap_or_else(|error| error.into_inner());
        let idle = pool.entry(server).or_default();
        if idle.len() < MAX_IDLE_PER_SERVER {
            idle.push(socket);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pool_caps_idle_sockets_per_server() {
        let client = UdpClient::new(None).expect("client");
        let server: SocketAddr = "127.0.0.1:9".parse().expect("server address");

        for _ in 0..MAX_IDLE_PER_SERVER + 4 {
            let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
            client.put(server, socket);
        }

        let mut kept = 0;
        while client.take(server).is_some() {
            kept += 1;
        }
        assert_eq!(kept, MAX_IDLE_PER_SERVER);
        assert!(client.take(server).is_none());
    }

    #[tokio::test]
    async fn pool_is_per_server() {
        let client = UdpClient::new(None).expect("client");
        let first: SocketAddr = "127.0.0.1:9".parse().expect("server address");
        let second: SocketAddr = "127.0.0.1:53".parse().expect("server address");

        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        client.put(first, socket);

        assert!(client.take(second).is_none());
        assert!(client.take(first).is_some());
    }
}
