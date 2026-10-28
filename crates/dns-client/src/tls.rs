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
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::verify_server_cert_signed_by_trust_anchor;
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;
use rustls::pki_types::pem::PemObject;
use rustls::server::ParsedCertificate;
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::{ClientError, exchange};

const MAX_IDLE_PER_SERVER: usize = 4;

type PoolKey = (SocketAddr, Option<String>);
type ConnectionPool = Arc<Mutex<HashMap<PoolKey, Vec<TlsStream<TcpStream>>>>>;

#[derive(Clone)]
pub struct TlsClient {
    connector: TlsConnector,
    /// Used when a forwarder has no `#auth-name`: the chain is still verified,
    /// but the certificate name is not, matching Unbound.
    connector_without_name: TlsConnector,
    pool: ConnectionPool,
}

impl TlsClient {
    /// Create a client that verifies servers against the configured roots.
    pub fn new(ca_bundle: Option<&Path>, use_system_ca: bool) -> Result<Self, ClientError> {
        let roots = load_roots(ca_bundle, use_system_ca)?;
        let config = client_config_with_roots(roots.clone(), &[])?;
        let without_name = chain_only_client_config(roots, &[])?;
        Ok(Self {
            connector: TlsConnector::from(config),
            connector_without_name: TlsConnector::from(without_name),
            pool: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Send one DNS message over TLS and wait for the response.
    ///
    /// `tls_name` is the certificate name from `#auth-name`. When it is
    /// `None`, any certificate that chains to a trusted CA is accepted, which
    /// is Unbound's behaviour for a forwarder without an auth name.
    pub async fn send_recv(
        &self,
        server: SocketAddr,
        tls_name: Option<&str>,
        query: &[u8],
        dur: Duration,
    ) -> Result<Vec<u8>, ClientError> {
        let key = (server, tls_name.map(str::to_owned));
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
        tls_name: Option<&str>,
        dur: Duration,
    ) -> Result<TlsStream<TcpStream>, ClientError> {
        let stream = timeout(dur, TcpStream::connect(server))
            .await
            .map_err(|_| ClientError::Timeout)??;
        stream.set_nodelay(true)?;
        let (connector, name) = match tls_name {
            Some(tls_name) => {
                let name = ServerName::try_from(tls_name.to_owned()).map_err(|error| {
                    ClientError::Tls(format!("invalid TLS server name: {error}"))
                })?;
                (&self.connector, name)
            }
            // No auth name: the verifier ignores the name. An IP address is
            // also what keeps rustls from sending SNI, as Unbound does.
            None => (
                &self.connector_without_name,
                ServerName::IpAddress(server.ip().into()),
            ),
        };
        timeout(dur, connector.connect(name, stream))
            .await
            .map_err(|_| ClientError::Timeout)?
            .map_err(|error| ClientError::Tls(error.to_string()))
    }

    fn take(&self, key: &PoolKey) -> Option<TlsStream<TcpStream>> {
        self.pool
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get_mut(key)
            .and_then(Vec::pop)
    }

    fn put(&self, key: PoolKey, stream: TlsStream<TcpStream>) {
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
    client_config_with_roots(load_roots(ca_bundle, use_system_ca)?, alpn)
}

/// Load the trust anchors used to authenticate upstream servers.
fn load_roots(ca_bundle: Option<&Path>, use_system_ca: bool) -> Result<RootCertStore, ClientError> {
    let mut roots = RootCertStore::empty();
    if use_system_ca {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    if let Some(path) = ca_bundle {
        for certificate in CertificateDer::pem_file_iter(path)
            .map_err(|error| ClientError::Tls(format!("invalid CA bundle: {error}")))?
        {
            let certificate = certificate
                .map_err(|error| ClientError::Tls(format!("invalid CA certificate: {error}")))?;
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
    Ok(roots)
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn client_config_with_roots(
    roots: RootCertStore,
    alpn: &[&[u8]],
) -> Result<Arc<ClientConfig>, ClientError> {
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|error| ClientError::Tls(error.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(Arc::new(config))
}

/// Build a configuration that verifies the certificate chain but accepts any
/// name in the certificate.
fn chain_only_client_config(
    roots: RootCertStore,
    alpn: &[&[u8]],
) -> Result<Arc<ClientConfig>, ClientError> {
    let provider = provider();
    let verifier = Arc::new(ChainOnlyVerifier {
        roots,
        supported: provider.signature_verification_algorithms,
    });
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| ClientError::Tls(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    config.alpn_protocols = alpn.iter().map(|protocol| protocol.to_vec()).collect();
    Ok(Arc::new(config))
}

/// Verify the certificate chain, validity period, and key usage, but skip the
/// subject-name check.
///
/// Unbound uses the same rule when a forwarder has no `#auth-name`: the
/// certificate must chain to a configured CA, but any name is accepted.
struct ChainOnlyVerifier {
    roots: RootCertStore,
    supported: WebPkiSupportedAlgorithms,
}

impl std::fmt::Debug for ChainOnlyVerifier {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChainOnlyVerifier")
            .finish_non_exhaustive()
    }
}

impl ServerCertVerifier for ChainOnlyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let certificate = ParsedCertificate::try_from(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(
            &certificate,
            &self.roots,
            intermediates,
            now,
            self.supported.all,
        )?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.supported)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.supported)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported.supported_schemes()
    }
}
