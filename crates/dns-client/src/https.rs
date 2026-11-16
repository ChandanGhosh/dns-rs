//! DNS over HTTPS (RFC 8484) using HTTP/2.
//!
//! One HTTP/2 connection is kept per (server, authority) pair. Hyper's
//! `SendRequest` is cloneable and multiplexes concurrent queries over the
//! connection, so it can be cached and shared directly. A failed request
//! evicts the cached sender and retries once on a fresh connection.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper::body::Bytes;
use hyper::client::conn::http2::SendRequest;
use hyper::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::ClientError;
use crate::tls::client_config;

const DNS_MESSAGE: &str = "application/dns-message";
const MAX_RESPONSE: usize = 65_535;
/// Maximum number of upstream HTTP/2 connections kept alive. Bounds the map
/// and the idle connections when a configuration churns through many
/// forwarder addresses.
const MAX_SENDERS: usize = 1024;

type SenderKey = (SocketAddr, String);
type SenderCache = Arc<Mutex<HashMap<SenderKey, SendRequest<Full<Bytes>>>>>;

#[derive(Clone)]
pub struct HttpsClient {
    connector: TlsConnector,
    senders: SenderCache,
}

impl HttpsClient {
    /// Create a client that verifies servers against the configured roots.
    pub fn new(ca_bundle: Option<&Path>, use_system_ca: bool) -> Result<Self, ClientError> {
        let config = client_config(ca_bundle, use_system_ca, &[b"h2"])?;
        Ok(Self {
            connector: TlsConnector::from(config),
            senders: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// POST one DNS message to `https://{host}{path}` and return the response.
    pub async fn send_recv(
        &self,
        server: SocketAddr,
        host: &str,
        path: &str,
        query: &[u8],
        dur: Duration,
    ) -> Result<Vec<u8>, ClientError> {
        let key = (server, host.to_owned());
        let mut last_error = None;

        for _ in 0..2 {
            let mut sender = match self.sender(server, host, dur).await {
                Ok(sender) => sender,
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            };

            match self.request(&mut sender, host, path, query, dur).await {
                Ok(response) => return Ok(response),
                Err(error) => {
                    self.senders.lock().await.remove(&key);
                    last_error = Some(error);
                }
            }
        }

        Err(last_error.unwrap_or(ClientError::Timeout))
    }

    async fn sender(
        &self,
        server: SocketAddr,
        host: &str,
        dur: Duration,
    ) -> Result<SendRequest<Full<Bytes>>, ClientError> {
        let key = (server, host.to_owned());
        if let Some(sender) = self.senders.lock().await.get(&key).cloned() {
            return Ok(sender);
        }

        let stream = timeout(dur, TcpStream::connect(server))
            .await
            .map_err(|_| ClientError::Timeout)??;
        stream.set_nodelay(true)?;
        let name = ServerName::try_from(host.to_owned())
            .map_err(|error| ClientError::Tls(format!("invalid HTTPS server name: {error}")))?;
        let stream = timeout(dur, self.connector.connect(name, stream))
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|error| ClientError::Tls(error.to_string()))?;

        let (sender, connection) = timeout(
            dur,
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream)),
        )
        .await
        .map_err(|_| ClientError::Timeout)?
        .map_err(|error| ClientError::Http(error.to_string()))?;
        tokio::spawn(async move {
            let _ = connection.await;
        });

        let mut senders = self.senders.lock().await;
        if senders.len() >= MAX_SENDERS
            && !senders.contains_key(&key)
            && let Some(evicted) = senders.keys().next().cloned()
        {
            senders.remove(&evicted);
        }
        senders.insert(key, sender.clone());
        drop(senders);
        Ok(sender)
    }

    async fn request(
        &self,
        sender: &mut SendRequest<Full<Bytes>>,
        host: &str,
        path: &str,
        query: &[u8],
        dur: Duration,
    ) -> Result<Vec<u8>, ClientError> {
        let uri = format!("https://{host}{path}");
        let request = Request::builder()
            .method("POST")
            .uri(uri)
            .header(CONTENT_TYPE, DNS_MESSAGE)
            .header(ACCEPT, DNS_MESSAGE)
            .header(CONTENT_LENGTH, query.len())
            .body(Full::new(Bytes::copy_from_slice(query)))
            .map_err(|error| ClientError::Http(error.to_string()))?;

        let response = timeout(dur, sender.send_request(request))
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|error| ClientError::Http(error.to_string()))?;
        if response.status() != hyper::StatusCode::OK {
            return Err(ClientError::Http(format!(
                "DoH server returned HTTP {}",
                response.status()
            )));
        }
        if let Some(content_type) = response.headers().get(CONTENT_TYPE) {
            let content_type = content_type.to_str().unwrap_or_default();
            if !content_type.starts_with(DNS_MESSAGE) {
                return Err(ClientError::Http(format!(
                    "DoH server returned content type {content_type:?}"
                )));
            }
        }

        let body = timeout(dur, response.into_body().collect())
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|error| ClientError::Http(error.to_string()))?
            .to_bytes();
        if body.len() > MAX_RESPONSE {
            return Err(ClientError::Http("DoH response is too large".to_owned()));
        }
        Ok(body.to_vec())
    }
}
