//! Pooled UDP sockets must be reused, skip stale datagrams, and be dropped
//! after a timed-out exchange.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dns_client::{ClientError, UdpClient};
use tokio::net::UdpSocket;

type Sources = Arc<Mutex<Vec<SocketAddr>>>;

fn record(sources: &Sources, src: SocketAddr) {
    sources.lock().expect("sources lock").push(src);
}

fn sources_of(sources: &Sources) -> Vec<SocketAddr> {
    sources.lock().expect("sources lock").clone()
}

#[tokio::test]
async fn sequential_queries_reuse_one_socket() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let server = socket.local_addr().expect("address");
    let sources: Sources = Arc::default();

    let server_task = {
        let sources = Arc::clone(&sources);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            for _ in 0..2 {
                let Ok((len, src)) = socket.recv_from(&mut buf).await else {
                    break;
                };
                record(&sources, src);
                let _ = socket.send_to(&buf[..len], src).await;
            }
        })
    };

    let client = UdpClient::new(None).expect("client");
    for id in [1u8, 2u8] {
        let query = [id, 0, 0, 0];
        let response = client
            .send_recv(server, &query, Duration::from_secs(2))
            .await
            .expect("response");
        assert_eq!(response, query);
    }
    server_task.await.expect("server task");

    let sources = sources_of(&sources);
    assert_eq!(sources.len(), 2);
    assert_eq!(
        sources[0], sources[1],
        "the second query must reuse the pooled socket"
    );
}

#[tokio::test]
async fn stale_wrong_txid_datagram_is_skipped() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let server = socket.local_addr().expect("address");

    tokio::spawn(async move {
        let mut buf = [0u8; 512];
        let Ok((len, src)) = socket.recv_from(&mut buf).await else {
            return;
        };
        // A short datagram and a reply for a different transaction ID, as a
        // pooled socket could still hold from an earlier exchange.
        let _ = socket.send_to(&[0xAB], src).await;
        let mut stale = vec![0xFF; len];
        let _ = socket.send_to(&stale, src).await;
        stale[..len].copy_from_slice(&buf[..len]);
        stale[0] ^= 0xFF;
        stale[1] ^= 0xFF;
        let _ = socket.send_to(&stale, src).await;
        let _ = socket.send_to(&buf[..len], src).await;
    });

    let client = UdpClient::new(None).expect("client");
    let query = [0x12, 0x34, 0x01, 0x00];
    let response = client
        .send_recv(server, &query, Duration::from_secs(2))
        .await
        .expect("response");
    assert_eq!(response, query, "only the matching txid may be returned");
}

#[tokio::test]
async fn timed_out_exchange_socket_is_not_reused() {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let server = socket.local_addr().expect("address");
    let sources: Sources = Arc::default();

    let server_task = {
        let sources = Arc::clone(&sources);
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            // First query goes unanswered so the client times out.
            let Ok((_, src)) = socket.recv_from(&mut buf).await else {
                return;
            };
            record(&sources, src);
            let Ok((len, src)) = socket.recv_from(&mut buf).await else {
                return;
            };
            record(&sources, src);
            let _ = socket.send_to(&buf[..len], src).await;
        })
    };

    let client = UdpClient::new(None).expect("client");
    let timed_out = client
        .send_recv(server, &[1, 0, 0, 0], Duration::from_millis(100))
        .await;
    assert!(
        matches!(timed_out, Err(ClientError::Timeout)),
        "expected a timeout, got {timed_out:?}"
    );

    let response = client
        .send_recv(server, &[2, 0, 0, 0], Duration::from_secs(2))
        .await
        .expect("response");
    assert_eq!(response, vec![2, 0, 0, 0]);
    server_task.await.expect("server task");

    let sources = sources_of(&sources);
    assert_eq!(sources.len(), 2);
    assert_ne!(
        sources[0], sources[1],
        "a socket from a timed-out exchange must not return to the pool"
    );
}
