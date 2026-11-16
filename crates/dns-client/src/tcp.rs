//! DNS over TCP (RFC 1035) with a small connection pool.
//!
//! Truncated UDP answers are retried over TCP. Keeping successful connections
//! around avoids a fresh three-way handshake for every fallback, which matters
//! for authoritative servers that truncate large RRsets consistently. As with
//! the TLS pool, an exchange failure drops every idle connection to that server
//! and the query is retried once on a fresh connection.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::{ClientError, exchange};

const MAX_IDLE_PER_SERVER: usize = 4;
/// Maximum number of upstream servers tracked per shard. Combined with
/// [`MAX_IDLE_PER_SERVER`] this bounds the map and the idle connections a
/// hostile zone can accumulate by churning nameserver addresses.
const MAX_SERVERS_PER_SHARD: usize = 32;
const SHARD_COUNT: usize = 32;

type TcpStreamList = Vec<TcpStream>;
type TcpPoolMap = HashMap<SocketAddr, TcpStreamList>;
type TcpPoolShard = Mutex<TcpPoolMap>;

#[derive(Clone, Default)]
struct ConnectionPool {
    shards: Arc<Vec<TcpPoolShard>>,
}

impl ConnectionPool {
    fn new() -> Self {
        let mut shards = Vec::with_capacity(SHARD_COUNT);
        for _ in 0..SHARD_COUNT {
            shards.push(Mutex::new(HashMap::new()));
        }
        Self {
            shards: Arc::new(shards),
        }
    }

    fn shard_idx(&self, key: SocketAddr) -> usize {
        let mut h: u64 = 1469598103934665603;
        match key.ip() {
            std::net::IpAddr::V4(v4) => {
                for b in v4.octets().iter() {
                    h ^= *b as u64;
                    h = h.wrapping_mul(1099511628211);
                }
            }
            std::net::IpAddr::V6(v6) => {
                for b in v6.octets().iter() {
                    h ^= *b as u64;
                    h = h.wrapping_mul(1099511628211);
                }
            }
        }
        h ^= key.port() as u64;
        h = h.wrapping_mul(1099511628211);
        (h as usize) % self.shards.len()
    }
}

#[derive(Clone, Default)]
pub struct TcpClient {
    pool: ConnectionPool,
}

impl TcpClient {
    pub fn new() -> Self {
        Self {
            pool: ConnectionPool::new(),
        }
    }

    pub async fn send_recv(
        &self,
        server: SocketAddr,
        query: &[u8],
        dur: Duration,
    ) -> Result<Vec<u8>, ClientError> {
        let mut last_error = None;
        let mut use_pool = true;

        for _ in 0..2 {
            let mut stream = match if use_pool { self.take(server) } else { None } {
                Some(stream) => stream,
                None => match self.connect(server, dur).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        last_error = Some(error);
                        use_pool = false;
                        continue;
                    }
                },
            };

            match exchange(&mut stream, query, dur).await {
                Ok(response) => {
                    self.put(server, stream);
                    return Ok(response);
                }
                Err(error) => {
                    // The peer may have closed an idle pooled connection. Drop
                    // every idle connection for this server: the remaining
                    // ones were likely closed at the same time, and retrying
                    // on another stale socket would fail the query.
                    last_error = Some(error);
                    self.clear(server);
                    use_pool = false;
                }
            }
        }

        Err(last_error.unwrap_or(ClientError::Timeout))
    }

    async fn connect(&self, server: SocketAddr, dur: Duration) -> Result<TcpStream, ClientError> {
        let stream = timeout(dur, TcpStream::connect(server))
            .await
            .map_err(|_| ClientError::Timeout)??;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    fn take(&self, server: SocketAddr) -> Option<TcpStream> {
        let idx = self.pool.shard_idx(server);
        self.pool.shards[idx]
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_mut(&server)
            .and_then(Vec::pop)
    }

    fn put(&self, server: SocketAddr, stream: TcpStream) {
        let idx = self.pool.shard_idx(server);
        let mut pool = self.pool.shards[idx]
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(idle) = pool.get_mut(&server) {
            if idle.len() < MAX_IDLE_PER_SERVER {
                idle.push(stream);
            }
            return;
        }
        if pool.len() >= MAX_SERVERS_PER_SHARD
            && let Some(evicted) = pool.keys().next().copied()
        {
            // Drop one server's idle connections so a zone that keeps rotating
            // nameserver addresses cannot grow the map without bound.
            pool.remove(&evicted);
        }
        pool.insert(server, vec![stream]);
    }

    fn clear(&self, server: SocketAddr) {
        let idx = self.pool.shard_idx(server);
        self.pool.shards[idx]
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&server);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::TcpClient;

    #[tokio::test]
    async fn reuses_a_pooled_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let handler = tokio::spawn(async move {
            // Accept two exchanges on the same connection.
            let (mut stream, _) = listener.accept().await.expect("accept");
            for _ in 0..2 {
                let mut lenbuf = [0u8; 2];
                stream.read_exact(&mut lenbuf).await.expect("len");
                let len = usize::from(u16::from_be_bytes(lenbuf));
                let mut buf = vec![0u8; len];
                stream.read_exact(&mut buf).await.expect("body");
                let mut out = Vec::with_capacity(len + 2);
                out.extend_from_slice(&(len as u16).to_be_bytes());
                out.extend_from_slice(&buf);
                stream.write_all(&out).await.expect("write");
            }
        });

        let client = TcpClient::new();
        let query = [0x11, 0x22, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let first = client
            .send_recv(addr, &query, Duration::from_secs(1))
            .await
            .expect("first");
        assert_eq!(&first[0..2], &query[0..2]);

        let query = [0x33, 0x44, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let second = client
            .send_recv(addr, &query, Duration::from_secs(1))
            .await
            .expect("second");
        assert_eq!(&second[0..2], &query[0..2]);

        handler.await.expect("handler");
    }

    #[tokio::test]
    async fn clears_idle_connections_on_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");

        let handler = tokio::spawn(async move {
            // The client retries once after a pooled/first failure; accept both
            // attempts and close without responding so reads fail promptly.
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let mut lenbuf = [0u8; 2];
                if stream.read_exact(&mut lenbuf).await.is_ok() {
                    let len = usize::from(u16::from_be_bytes(lenbuf));
                    let mut buf = vec![0u8; len];
                    let _ = stream.read_exact(&mut buf).await;
                }
                drop(stream);
            }
        });

        let client = TcpClient::new();
        let query = [0x55, 0x66, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        let error = client
            .send_recv(addr, &query, Duration::from_secs(1))
            .await
            .expect_err("expected failure");
        // Closing the stream without a framed response produces an I/O error.
        assert!(matches!(error, crate::ClientError::Io(_)));

        handler.await.expect("handler");
    }
}
