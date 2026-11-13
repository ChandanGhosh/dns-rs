//! Connection-limit behavior for the plain TCP listener.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dns_config::{Config, ListenAddress, ThreadCount};
use dns_proto::{
    Message, MessageType, Name, OpCode, Query, RecordType, ResponseCode, decode, encode,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

struct TestServer {
    addr: SocketAddr,
    shutdown: CancellationToken,
}

impl TestServer {
    async fn start(incoming_num_tcp: usize) -> Self {
        let port = free_port();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

        let mut config = Config::default();
        config.server.interfaces = vec![ListenAddress::new(addr.ip(), Some(port))];
        config.server.port = port;
        config.server.num_threads = ThreadCount::Fixed(1);
        config.server.incoming_num_tcp = incoming_num_tcp;
        config.server.do_ip6 = false;
        config.server.do_udp = false;
        config.server.dnssec_validation = false;

        let shutdown = CancellationToken::new();
        let server_shutdown = shutdown.clone();
        tokio::spawn(async move {
            dns_server::serve(Arc::new(config), server_shutdown)
                .await
                .expect("server runs");
        });
        wait_ready(addr).await;
        // The readiness probe may still be releasing its slot.
        tokio::time::sleep(Duration::from_millis(50)).await;

        Self { addr, shutdown }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

#[tokio::test]
async fn tcp_connection_limit_applies_backpressure() {
    let server = TestServer::start(1).await;

    // Hold the only slot open with a completed query.
    let mut first = TcpStream::connect(server.addr)
        .await
        .expect("first connect");
    send_query(&mut first).await;
    let first_response = timeout(Duration::from_secs(2), read_response(&mut first))
        .await
        .expect("first query does not time out")
        .expect("first response");
    assert_noerror(&first_response);

    // A second connection is accepted by the kernel but must wait for a slot.
    let mut second = TcpStream::connect(server.addr)
        .await
        .expect("second connect");
    send_query(&mut second).await;
    assert!(
        timeout(Duration::from_millis(300), read_response(&mut second))
            .await
            .is_err(),
        "second connection must wait while the limit is reached"
    );

    // Releasing the first connection lets the queued connection proceed.
    drop(first);
    let second_response = timeout(Duration::from_secs(3), read_response(&mut second))
        .await
        .expect("queued connection is served after a slot frees")
        .expect("second response");
    assert_noerror(&second_response);
}

fn assert_noerror(wire: &[u8]) {
    let message = decode(wire).expect("decode response");
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert!(!message.answers.is_empty());
}

async fn send_query(stream: &mut TcpStream) {
    let mut message = Message::new(0x1234, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.queries.push(Query::query(
        Name::from_ascii("localhost.").expect("name"),
        RecordType::A,
    ));
    let wire = encode(&message).expect("encode query");
    let mut out = Vec::with_capacity(wire.len() + 2);
    out.extend_from_slice(&(wire.len() as u16).to_be_bytes());
    out.extend_from_slice(&wire);
    stream.write_all(&out).await.expect("write query");
}

async fn read_response(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut lenbuf = [0u8; 2];
    stream.read_exact(&mut lenbuf).await?;
    let mut response = vec![0u8; usize::from(u16::from_be_bytes(lenbuf))];
    stream.read_exact(&mut response).await?;
    Ok(response)
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("local address").port()
}

async fn wait_ready(addr: SocketAddr) {
    for _ in 0..100 {
        if TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("listener at {addr} did not become ready");
}
