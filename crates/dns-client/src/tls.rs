//! DNS over TLS (RFC 7858) with a small connection pool.
//!
//! Each server gets a pool of idle TLS connections. A query takes a
//! connection exclusively, writes the two-byte length prefix and the message,
//! then returns the connection to the pool. Connections that fail are dropped
//! and the query is retried once on a fresh connection, which also handles
//! servers that close idle connections.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::ClientConfig;
use rustls::RootCertStore;
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::{ClientError, exchange};

const MAX_IDLE_PER_SERVER: usize = 4;

type PoolKey = (SocketAddr, String);
type ConnectionPool = Arc<Mutex<HashMap<PoolKey, Vec<TlsStream<TcpStream>>>>>;

#[derive(Clone)]
pub struct TlsClient {
    connector: TlsConnector,
    pool: ConnectionPool,
}

impl TlsClient {
    /// Create a client that verifies servers against the configured roots.
    pub fn new(ca_bundle: Option<&Path>, use_system_ca: bool) -> Result<Self, ClientError> {
        let config = client_config(ca_bundle, use_system_ca, &[])?;
        Ok(Self {
            connector: TlsConnector::from(config),
            pool: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Send one DNS message over TLS and wait for the response.
    pub async fn send_recv(
        &self,
        server: SocketAddr,
        tls_name: &str,
        query: &[u8],
        dur: Duration,
    ) -> Result<Vec<u8>, ClientError> {
        let key = (server, tls_name.to_owned());
        let mut last_error = None;

        for _ in 0..2 {
            let mut stream = match self.take(&key) {
                Some(stream) => stream,
                None => match self.connect(server, tls_name, dur).await {
                    Ok(stream) => stream,
                    Err(error) => {
                        last_error = Some(error);
                        continue;
                    }
                },
            };

            match exchange(&mut stream, query, dur).await {
                Ok(response) => {
                    self.put(key, stream);
                    return Ok(response);
                }
                Err(error) => {
                    // The pooled connection may have been closed by the peer.
                    // Drop it and try a fresh one on the next iteration.
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or(ClientError::Timeout))
    }

    async fn connect(
        &self,
        server: SocketAddr,
        tls_name: &str,
        dur: Duration,
    ) -> Result<TlsStream<TcpStream>, ClientError> {
        let stream = timeout(dur, TcpStream::connect(server))
            .await
            .map_err(|_| ClientError::Timeout)??;
        stream.set_nodelay(true)?;
        let name = ServerName::try_from(tls_name.to_owned())
            .map_err(|error| ClientError::Tls(format!("invalid TLS server name: {error}")))?;
        timeout(dur, self.connector.connect(name, stream))
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|error| ClientError::Tls(error.to_string()))
    }

    fn take(&self, key: &(SocketAddr, String)) -> Option<TlsStream<TcpStream>> {
        self.pool
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_mut(key)
            .and_then(Vec::pop)
    }

    fn put(&self, key: (SocketAddr, String), stream: TlsStream<TcpStream>) {
        let mut pool = self.pool.lock().unwrap_or_else(|error| error.into_inner());
        let idle = pool.entry(key).or_default();
        if idle.len() < MAX_IDLE_PER_SERVER {
            idle.push(stream);
        }
    }
}

/// Build a rustls client configuration with optional system roots and a PEM
/// bundle, and the given ALPN protocols.
pub(crate) fn client_config(
    ca_bundle: Option<&Path>,
    use_system_ca: bool,
    alpn: &[&[u8]],
) -> Result<Arc<ClientConfig>, ClientError> {
    let mut roots = RootCertStore::empty();
    if use_system_ca {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    if let Some(path) = ca_bundle {
        let file = std::fs::File::open(path)?;
        let mut reader = std::io::BufReader::new(file);
        for certificate in rustls_pemfile::certs(&mut reader) {
            let certificate = certificate?;
            roots
                .add(certificate)
                .map_err(|error| ClientError::Tls(format!("invalid CA certificate: {error}")))?;
        }
    }
    if roots.is_empty() {
        return Err(ClientError::Tls(
            "no upstream CA certificates configured".to_owned(),
        ));
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| ClientError::Tls(error.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(Arc::new(config))
}
