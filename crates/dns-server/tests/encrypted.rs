//! End-to-end tests for DNS-over-TLS and DNS-over-HTTPS.
//!
//! Each test starts the real server with a self-signed certificate, then uses
//! the production clients to query it. The upstream tests point an iterator
//! forward zone at the same server, so both the downstream listener and the
//! upstream transport are exercised together.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use dns_client::{HttpsClient, TlsClient};
use dns_config::{Config, ListenAddress};
use dns_iter::{ForwardServer, ForwardTransport, ForwardZone, IteratorConfig, IteratorResolver};
use dns_proto::{
    Message, MessageType, Name, OpCode, Query, RData, RecordType, ResponseCode, decode, encode,
};
use tokio_util::sync::CancellationToken;

struct TestServer {
    shutdown: CancellationToken,
    dot: SocketAddr,
    doh: SocketAddr,
    cert: PathBuf,
    _directory: PathBuf,
}

impl TestServer {
    async fn start() -> Self {
        Self::start_with_incoming(10).await
    }

    async fn start_with_incoming(incoming_num_tcp: usize) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "dns-rs-encrypted-{}-{}",
            std::process::id(),
            unique()
        ));
        std::fs::create_dir_all(&directory).expect("create test directory");
        let key_path = directory.join("key.pem");
        let cert_path = directory.join("cert.pem");

        let rcgen::CertifiedKey { cert, key_pair } = rcgen::generate_simple_self_signed(vec![
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
        ])
        .expect("generate certificate");
        std::fs::write(&cert_path, cert.pem()).expect("write certificate");
        std::fs::write(&key_path, key_pair.serialize_pem()).expect("write key");

        let dot = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), free_port());
        let doh = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), free_port());

        let mut config = Config::default();
        config.server.interfaces = vec![
            ListenAddress::new(dot.ip(), Some(dot.port())),
            ListenAddress::new(doh.ip(), Some(doh.port())),
        ];
        config.server.tls_service_key = Some(key_path);
        config.server.tls_service_pem = Some(cert_path.clone());
        config.server.tls_port = dot.port();
        config.server.https_port = doh.port();
        config.server.dnssec_validation = false;
        config.server.incoming_num_tcp = incoming_num_tcp;

        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        tokio::spawn(async move {
            dns_server::serve(Arc::new(config), server_shutdown)
                .await
                .expect("server runs");
        });
        wait_ready(dot).await;
        wait_ready(doh).await;

        Self {
            shutdown,
            dot,
            doh,
            cert: cert_path,
            _directory: directory,
        }
    }

    fn tls_client(&self) -> TlsClient {
        TlsClient::new(Some(&self.cert), false).expect("TLS client")
    }

    fn https_client(&self) -> HttpsClient {
        HttpsClient::new(Some(&self.cert), false).expect("HTTPS client")
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

#[tokio::test]
async fn downstream_dot_answers_and_reuses_connections() {
    let server = TestServer::start().await;
    let client = server.tls_client();
    let wire = query("localhost.", RecordType::A);

    for _ in 0..2 {
        let response = client
            .send_recv(server.dot, "localhost", &wire, Duration::from_secs(5))
            .await
            .expect("DoT response");
        let message = decode(&response).expect("decode response");
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert!(message.answers.iter().any(|record| {
            matches!(record.data, RData::A(address) if address.0 == Ipv4Addr::LOCALHOST)
        }));
    }
}

#[tokio::test]
async fn downstream_dot_rejects_the_wrong_server_name() {
    let server = TestServer::start().await;
    let client = server.tls_client();
    let result = client
        .send_recv(
            server.dot,
            "wrong.example",
            &query("localhost.", RecordType::A),
            Duration::from_secs(3),
        )
        .await;
    assert!(result.is_err(), "certificate verification must fail");
}

/// `dig` offers the `dot` ALPN token. A DoT listener that advertises its own
/// ALPN list would reject it with `no_application_protocol`.
#[tokio::test]
async fn downstream_dot_accepts_clients_that_offer_dot_alpn() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let server = TestServer::start().await;
    let connector = tls_connector(&server.cert, Some(b"dot"));

    let stream = tokio::net::TcpStream::connect(server.dot)
        .await
        .expect("connect");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");
    let mut stream = connector
        .connect(name, stream)
        .await
        .expect("handshake with the dot ALPN");

    let wire = query("localhost.", RecordType::A);
    let mut out = vec![(wire.len() >> 8) as u8, wire.len() as u8];
    out.extend_from_slice(&wire);
    stream.write_all(&out).await.expect("write query");

    let mut lenbuf = [0u8; 2];
    stream.read_exact(&mut lenbuf).await.expect("read length");
    let mut response = vec![0u8; usize::from(u16::from_be_bytes(lenbuf))];
    stream
        .read_exact(&mut response)
        .await
        .expect("read response");

    let message = decode(&response).expect("decode response");
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
}

/// DoT and plain TCP share the same `incoming-num-tcp` budget. A second TLS
/// handshake must wait until the first connection closes.
#[tokio::test]
async fn downstream_dot_connections_share_the_tcp_limit() {
    let server = TestServer::start_with_incoming(1).await;
    let connector = tls_connector(&server.cert, None);
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("server name");

    let first = tokio::net::TcpStream::connect(server.dot)
        .await
        .expect("first connect");
    let first = connector
        .connect(name.clone(), first)
        .await
        .expect("first handshake");
    assert!(
        tokio::time::timeout(
            Duration::from_millis(300),
            connector.connect(
                name.clone(),
                tokio::net::TcpStream::connect(server.dot)
                    .await
                    .expect("second connect")
            )
        )
        .await
        .is_err(),
        "second handshake must wait while the connection limit is reached"
    );

    drop(first);
    let third = tokio::net::TcpStream::connect(server.dot)
        .await
        .expect("third connect");
    tokio::time::timeout(Duration::from_secs(3), connector.connect(name, third))
        .await
        .expect("handshake proceeds after a slot frees")
        .expect("third handshake");
}

fn tls_connector(cert: &Path, alpn: Option<&[u8]>) -> tokio_rustls::TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    let pem = std::fs::read(cert).expect("read certificate");
    for certificate in rustls_pemfile::certs(&mut pem.as_slice()) {
        roots
            .add(certificate.expect("certificate"))
            .expect("add root");
    }
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    if let Some(protocol) = alpn {
        config.alpn_protocols = vec![protocol.to_vec()];
    }
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

#[tokio::test]
async fn downstream_doh_answers_and_reuses_the_http2_connection() {
    let server = TestServer::start().await;
    let client = server.https_client();
    let wire = query("localhost.", RecordType::A);

    for _ in 0..2 {
        let response = client
            .send_recv(
                server.doh,
                "localhost",
                "/dns-query",
                &wire,
                Duration::from_secs(5),
            )
            .await
            .expect("DoH response");
        let message = decode(&response).expect("decode response");
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert!(message.answers.iter().any(|record| {
            matches!(record.data, RData::A(address) if address.0 == Ipv4Addr::LOCALHOST)
        }));
    }
}

#[tokio::test]
async fn upstream_dot_forwarder_resolves() {
    let server = TestServer::start().await;
    let config = forward_config(server.dot, ForwardTransport::Tls, None, &server.cert);
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");
    let message = resolver
        .resolve("localhost.", RecordType::A)
        .await
        .expect("forwarded DoT resolution");
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert!(message.answers.iter().any(|record| {
        matches!(record.data, RData::A(address) if address.0 == Ipv4Addr::LOCALHOST)
    }));
}

#[tokio::test]
async fn upstream_doh_forwarder_resolves() {
    let server = TestServer::start().await;
    let config = forward_config(
        server.doh,
        ForwardTransport::Https,
        Some("/dns-query"),
        &server.cert,
    );
    let resolver = IteratorResolver::with_config(config, None).expect("resolver");
    let message = resolver
        .resolve("localhost.", RecordType::A)
        .await
        .expect("forwarded DoH resolution");
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert!(message.answers.iter().any(|record| {
        matches!(record.data, RData::A(address) if address.0 == Ipv4Addr::LOCALHOST)
    }));
}

fn forward_config(
    addr: SocketAddr,
    transport: ForwardTransport,
    path: Option<&str>,
    cert: &Path,
) -> IteratorConfig {
    IteratorConfig {
        case_randomization: false,
        cookies: false,
        forward_zones: vec![ForwardZone {
            zone: Name::root(),
            servers: vec![ForwardServer {
                addr,
                transport,
                tls_name: Some("localhost".to_owned()),
                path: path.map(str::to_owned),
            }],
            forward_first: false,
        }],
        tls_cert_bundle: Some(cert.to_path_buf()),
        tls_use_system_ca: false,
        ..IteratorConfig::default()
    }
}

fn query(name: &str, qtype: RecordType) -> Vec<u8> {
    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message
        .queries
        .push(Query::query(Name::from_ascii(name).expect("name"), qtype));
    encode(&message).expect("encode query")
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("local address").port()
}

async fn wait_ready(addr: SocketAddr) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("listener at {addr} did not become ready");
}

fn unique() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos()
}
