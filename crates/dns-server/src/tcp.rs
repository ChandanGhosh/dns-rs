use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::pipeline::{QueryPipeline, Transport};

/// Non-consuming readability probe used to notice a client disconnect while a
/// query is still resolving.
///
/// The explicit `impl Future + Send` return type is required: an `async fn` in
/// a trait does not promise that the returned future is `Send`, but this
/// future is awaited inside a spawned connection task.
#[allow(clippy::manual_async_fn)]
pub trait Probe {
    fn probe(&self) -> impl std::future::Future<Output = std::io::Result<usize>> + Send;
}

#[allow(clippy::manual_async_fn)]
impl Probe for TcpStream {
    fn probe(&self) -> impl std::future::Future<Output = std::io::Result<usize>> + Send {
        async move {
            let mut byte = [0u8; 1];
            self.peek(&mut byte).await
        }
    }
}

#[allow(clippy::manual_async_fn)]
impl Probe for tokio_rustls::server::TlsStream<TcpStream> {
    fn probe(&self) -> impl std::future::Future<Output = std::io::Result<usize>> + Send {
        async move {
            let mut byte = [0u8; 1];
            self.get_ref().0.peek(&mut byte).await
        }
    }
}

pub async fn run(
    listener: TcpListener,
    pipeline: Arc<QueryPipeline>,
    shutdown: CancellationToken,
    connections: Arc<Semaphore>,
) -> std::io::Result<()> {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            result = listener.accept() => {
                match result {
                    Ok((stream, client)) => {
                        // Wait for a connection slot before spawning. This
                        // applies backpressure to the accept queue instead of
                        // letting idle clients grow unbounded tasks.
                        let permit = tokio::select! {
                            _ = shutdown.cancelled() => break,
                            permit = Arc::clone(&connections).acquire_owned() => {
                                match permit {
                                    Ok(permit) => permit,
                                    Err(_) => break,
                                }
                            }
                        };
                        let pipeline = Arc::clone(&pipeline);
                        tokio::spawn(async move {
                            let _permit = permit;
                            serve_connection(stream, client, pipeline, Transport::Tcp).await;
                        });
                    }
                    Err(err) => {
                        debug!(%err, "TCP accept error");
                    }
                }
            }
        }
    }
    Ok(())
}

/// Serve length-prefixed DNS messages on one connection until it closes.
pub async fn serve_connection<S>(
    mut stream: S,
    client: SocketAddr,
    pipeline: Arc<QueryPipeline>,
    transport: Transport,
) where
    S: AsyncRead + AsyncWrite + Unpin + Probe,
{
    let mut lenbuf = [0u8; 2];
    loop {
        match tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut lenbuf)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }
        let len = usize::from(u16::from_be_bytes(lenbuf));
        if len == 0 {
            break;
        }
        let mut buf = vec![0u8; len];
        match tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut buf)).await {
            Ok(Ok(_)) => {}
            _ => break,
        }

        // While the query resolves, watch the socket without consuming data.
        // EOF means the client is gone, so the upstream subquery tree can be
        // dropped. A readable socket means the client pipelined another query;
        // in that case stop probing and let the current query finish.
        let cancel = CancellationToken::new();
        let mut handle =
            Box::pin(pipeline.handle_with_cancel(&buf, client, transport, cancel.clone()));
        let mut probing = true;
        let response = loop {
            if !probing {
                break handle.await;
            }
            tokio::select! {
                biased;
                response = &mut handle => break response,
                result = stream.probe() => {
                    match result {
                        Ok(0) => {
                            debug!(%client, "client closed while a query was in flight");
                            cancel.cancel();
                            return;
                        }
                        Ok(_) => probing = false,
                        Err(error) => {
                            debug!(%client, %error, "client probe failed");
                            cancel.cancel();
                            return;
                        }
                    }
                }
            }
        };
        let Some(response) = response else {
            break;
        };
        let mut out = Vec::with_capacity(response.len() + 2);
        out.extend_from_slice(&(response.len() as u16).to_be_bytes());
        out.extend_from_slice(&response);
        if stream.write_all(&out).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::Probe;

    #[tokio::test]
    async fn probe_reports_eof_without_consuming_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let accept = tokio::spawn(async move { listener.accept().await.expect("accept").0 });

        let mut client = TcpStream::connect(addr).await.expect("connect");
        let mut server = accept.await.expect("accept task");

        assert!(
            tokio::time::timeout(Duration::from_millis(50), server.probe())
                .await
                .is_err(),
            "probe must wait when the peer is idle"
        );

        client.write_all(b"x").await.expect("write");
        assert_eq!(server.probe().await.expect("probe data"), 1);

        let mut byte = [0u8; 1];
        server.read_exact(&mut byte).await.expect("read");
        assert_eq!(byte, [b'x']);

        drop(client);
        assert_eq!(server.probe().await.expect("probe eof"), 0);
    }
}
