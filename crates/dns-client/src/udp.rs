use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dns_proto::buffer_pool::{BufferPool, PooledReply};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::ClientError;
use crate::limits::{SHARD_COUNT, idle_pool_capacity, pool_parameters};

/// Ideal number of idle sockets per upstream server before the descriptor
/// budget scales it down.
const MAX_IDLE_PER_SERVER: usize = 16;

type UdpSocketList = Vec<UdpSocket>;
type UdpPoolMap = HashMap<SocketAddr, UdpSocketList>;
type UdpPoolShard = Mutex<UdpPoolMap>;

#[derive(Clone)]
struct SocketPool {
    shards: Arc<Vec<UdpPoolShard>>,
    idle_per_server: usize,
    servers_per_shard: usize,
}

impl Default for SocketPool {
    fn default() -> Self {
        let (idle_per_server, servers_per_shard) =
            pool_parameters(idle_pool_capacity(), MAX_IDLE_PER_SERVER);
        let mut shards = Vec::with_capacity(SHARD_COUNT);
        for _ in 0..SHARD_COUNT {
            shards.push(Mutex::new(HashMap::new()));
        }
        Self {
            shards: Arc::new(shards),
            idle_per_server,
            servers_per_shard,
        }
    }
}

impl std::fmt::Debug for SocketPool {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("SocketPool").finish_non_exhaustive()
    }
}

fn shard_index(shards: usize, key: SocketAddr) -> usize {
    let mut h: u64 = 1469598103934665603;
    let ip = key.ip();
    match ip {
        IpAddr::V4(v4) => {
            for b in v4.octets().iter() {
                h ^= *b as u64;
                h = h.wrapping_mul(1099511628211);
            }
        }
        IpAddr::V6(v6) => {
            for b in v6.octets().iter() {
                h ^= *b as u64;
                h = h.wrapping_mul(1099511628211);
            }
        }
    }
    let port = key.port();
    h ^= port as u64;
    h = h.wrapping_mul(1099511628211);
    (h as usize) % shards
}

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
/// to the pool, so a late reply has nowhere to land. Responses are read into
/// buffers borrowed from a shared [`BufferPool`], so steady-state exchanges
/// do not allocate and zero-fill a 64 KiB receive buffer per query. Pool
/// capacity is derived from the process descriptor limit, so a container with
/// a low `RLIMIT_NOFILE` cannot hit `EMFILE` by filling the pool.
#[derive(Clone, Debug, Default)]
pub struct UdpClient {
    bind_addr: Option<IpAddr>,
    pool: SocketPool,
    recv_pool: BufferPool,
}

impl UdpClient {
    /// Create a client, optionally binding outgoing sockets to `bind_addr`.
    pub fn new(bind_addr: Option<SocketAddr>) -> std::io::Result<Self> {
        Ok(Self {
            bind_addr: bind_addr.map(|addr| addr.ip()),
            pool: SocketPool::default(),
            recv_pool: BufferPool::default(),
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
    /// The response datagram backed by a pooled buffer, exposing exactly the
    /// bytes received; dropping it returns the buffer to the pool
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
    ) -> Result<PooledReply, ClientError> {
        let socket = match self.take(server) {
            Some(socket) => socket,
            None => self.connect(server).await?,
        };
        socket.send(query).await?;

        // EDNS can advertise up to 65535 bytes, so the receive buffer spans a
        // full-size message; it comes from the pool instead of being freshly
        // allocated and zero-filled on every exchange.
        let mut buf = self.recv_pool.get();
        let received = timeout(dur, async {
            loop {
                let len = socket.recv(&mut buf).await?;
                // Skip stale datagrams left over from an earlier exchange on
                // this pooled socket. `len >= 2` ensures the compared bytes
                // were actually received rather than stale buffer contents.
                if len >= 2 && query.len() >= 2 && buf[..2] == query[..2] {
                    return Ok(len);
                }
            }
        })
        .await;

        match received {
            Ok(Ok(len)) => {
                self.put(server, socket);
                Ok(PooledReply::new(buf, len))
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
        let idx = shard_index(self.pool.shards.len(), server);
        self.pool.shards[idx]
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_mut(&server)
            .and_then(Vec::pop)
    }

    fn put(&self, server: SocketAddr, socket: UdpSocket) {
        let idx = shard_index(self.pool.shards.len(), server);
        let mut pool = self.pool.shards[idx]
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(idle) = pool.get_mut(&server) {
            if idle.len() < self.pool.idle_per_server {
                idle.push(socket);
            }
            return;
        }
        if pool.len() >= self.pool.servers_per_shard
            && let Some(evicted) = pool.keys().next().copied()
        {
            // Drop one server's idle sockets so a zone that keeps rotating
            // nameserver addresses cannot grow the map without bound.
            pool.remove(&evicted);
        }
        pool.insert(server, vec![socket]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use crate::ClientError;

    #[tokio::test]
    async fn times_out_when_the_server_never_responds() {
        // Keep the socket bound but never read from it so datagrams are silently
        // dropped and the client hits its deadline.
        let server = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = server.local_addr().expect("addr");

        let client = UdpClient::new(None).expect("client");
        let query = [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let error = client
            .send_recv(addr, &query, Duration::from_millis(50))
            .await
            .expect_err("timeout expected");

        assert!(matches!(error, ClientError::Timeout));
        drop(server);
    }

    #[tokio::test]
    async fn reuses_an_idle_socket_for_the_same_server() {
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");

        let handler = tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (len, peer) = listener.recv_from(&mut buf).await.expect("recv");
            listener.send_to(&buf[..len], peer).await.expect("send");
            let (len, peer) = listener.recv_from(&mut buf).await.expect("recv");
            listener.send_to(&buf[..len], peer).await.expect("send");
        });

        let client = UdpClient::new(None).expect("client");
        let query = [0xaa, 0xbb, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let first = client
            .send_recv(addr, &query, Duration::from_secs(1))
            .await
            .expect("first exchange");
        assert_eq!(&first[..2], &query[..2]);

        let query = [0xcc, 0xdd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let second = client
            .send_recv(addr, &query, Duration::from_secs(1))
            .await
            .expect("second exchange");
        assert_eq!(&second[..2], &query[..2]);

        handler.await.expect("handler");
    }

    #[tokio::test]
    async fn pool_bounds_the_tracked_server_count() {
        let client = UdpClient::new(None).expect("client");
        let limit = client.pool.servers_per_shard;
        // Fill every shard to capacity; `put` only needs a full map to
        // exercise eviction.
        for shard in client.pool.shards.iter() {
            let mut map = shard.lock().unwrap_or_else(|error| error.into_inner());
            for port in 0..limit {
                map.insert(SocketAddr::from(([127, 0, 0, 1], port as u16)), Vec::new());
            }
        }

        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let server = SocketAddr::from(([192, 0, 2, 1], 53));
        client.put(server, socket);

        let idx = shard_index(client.pool.shards.len(), server);
        let map = client.pool.shards[idx]
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        assert_eq!(map.len(), limit);
        assert!(map.contains_key(&server));
    }
}
