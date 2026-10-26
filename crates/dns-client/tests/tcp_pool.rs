//! Plain TCP fallback must reuse idle connections.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use dns_client::TcpClient;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn sequential_queries_reuse_one_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let server = listener.local_addr().expect("address");
    let connections = Arc::new(AtomicUsize::new(0));

    {
        let connections = Arc::clone(&connections);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                connections.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    loop {
                        let mut lenbuf = [0u8; 2];
                        if stream.read_exact(&mut lenbuf).await.is_err() {
                            return;
                        }
                        let len = usize::from(u16::from_be_bytes(lenbuf));
                        let mut query = vec![0u8; len];
                        if stream.read_exact(&mut query).await.is_err() {
                            return;
                        }
                        let mut framed = Vec::with_capacity(query.len() + 2);
                        framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
                        framed.extend_from_slice(&query);
                        if stream.write_all(&framed).await.is_err() {
                            return;
                        }
                    }
                });
            }
        });
    }

    let client = TcpClient::new();
    for id in [1u8, 2u8] {
        let response = client
            .send_recv(server, &[id, 0, 0, 0], Duration::from_secs(2))
            .await
            .expect("response");
        assert_eq!(response, vec![id, 0, 0, 0]);
    }

    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "the second query must reuse the pooled connection"
    );
}

#[tokio::test]
async fn closed_pooled_connection_is_replaced() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let server: SocketAddr = listener.local_addr().expect("address");
    let connections = Arc::new(AtomicUsize::new(0));

    {
        let connections = Arc::clone(&connections);
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let _count = connections.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let mut lenbuf = [0u8; 2];
                    if stream.read_exact(&mut lenbuf).await.is_err() {
                        return;
                    }
                    let len = usize::from(u16::from_be_bytes(lenbuf));
                    let mut query = vec![0u8; len];
                    if stream.read_exact(&mut query).await.is_err() {
                        return;
                    }
                    let mut framed = Vec::with_capacity(query.len() + 2);
                    framed.extend_from_slice(&(query.len() as u16).to_be_bytes());
                    framed.extend_from_slice(&query);
                    let _ = stream.write_all(&framed).await;
                    // Close immediately after replying, simulating a server
                    // that does not keep idle TCP connections open.
                });
            }
        });
    }

    let client = TcpClient::new();
    let first = client
        .send_recv(server, &[1, 0, 0, 0], Duration::from_secs(2))
        .await
        .expect("first response");
    assert_eq!(first, vec![1, 0, 0, 0]);

    // The pooled connection is closed; the client must transparently connect
    // again and still return a response.
    let second = client
        .send_recv(server, &[2, 0, 0, 0], Duration::from_secs(2))
        .await
        .expect("second response");
    assert_eq!(second, vec![2, 0, 0, 0]);
    assert_eq!(connections.load(Ordering::SeqCst), 2);
}
