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

type ConnectionPool = Arc<Mutex<HashMap<SocketAddr, Vec<TcpStream>>>>;

#[derive(Clone, Default)]
pub struct TcpClient {
    pool: ConnectionPool,
}

impl TcpClient {
    pub fn new() -> Self {
        Self::default()
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
        self.pool
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_mut(&server)
            .and_then(Vec::pop)
    }

    fn put(&self, server: SocketAddr, stream: TcpStream) {
        let mut pool = self.pool.lock().unwrap_or_else(|error| error.into_inner());
        let idle = pool.entry(server).or_default();
        if idle.len() < MAX_IDLE_PER_SERVER {
            idle.push(stream);
        }
    }

    /// Drop all idle connections to `server`.
    fn clear(&self, server: SocketAddr) {
        self.pool
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remove(&server);
    }
}
