//! Downstream TLS material for DNS-over-TLS and DNS-over-HTTPS.

use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;

use dns_config::ServerConfig;
use rustls::ServerConfig as RustlsServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::TlsAcceptor;

use crate::ServerError;

/// TLS acceptors derived from the configured certificate and key.
pub struct TlsMaterial {
    /// DoT acceptor. It advertises no ALPN, because ALPN is optional for
    /// DNS-over-TLS and some clients (notably `dig`) offer only `dot`.
    pub dot: TlsAcceptor,
    /// DoH acceptor, preferring HTTP/2 and falling back to HTTP/1.1.
    pub doh: TlsAcceptor,
}

/// Load the configured certificate chain and private key.
///
/// Returns `None` when no TLS service material is configured, which disables
/// both DoT and DoH listeners.
pub fn load(server: &ServerConfig) -> Result<Option<TlsMaterial>, ServerError> {
    let (Some(key_path), Some(cert_path)) = (&server.tls_service_key, &server.tls_service_pem)
    else {
        return Ok(None);
    };

    let certificates: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(File::open(cert_path)?))
            .collect::<Result<_, _>>()?;
    if certificates.is_empty() {
        return Err(ServerError::Tls(format!(
            "{} contains no certificates",
            cert_path.display()
        )));
    }

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut BufReader::new(
        File::open(key_path)?,
    ))?
    .ok_or_else(|| ServerError::Tls(format!("{} contains no private key", key_path.display())))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = RustlsServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| ServerError::Tls(error.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certificates.clone(), key.clone_key())
        .map_err(|error| ServerError::Tls(error.to_string()))?;

    // DoH negotiates HTTP/2 (preferred) or HTTP/1.1. DoT deliberately leaves
    // ALPN empty: a server that lists protocols rejects clients offering an
    // unlisted one, and `dig` offers `dot`.
    let mut doh = config.clone();
    doh.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(Some(TlsMaterial {
        dot: TlsAcceptor::from(Arc::new(config)),
        doh: TlsAcceptor::from(Arc::new(doh)),
    }))
}
