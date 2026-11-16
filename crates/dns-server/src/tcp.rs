use std::io::IoSlice;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::pipeline::{PipelineHandle, Transport};
use dns_proto::buffer_pool::BufferPool;
use dns_proto::{decode, encode};

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
    pipeline: PipelineHandle,
    shutdown: CancellationToken,
    connections: Arc<Semaphore>,
) -> std::io::Result<()> {
    let pool = BufferPool::default();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            result = listener.accept() => {
                match result {
                    Ok((stream, client)) => {
                        if let Err(err) = stream.set_nodelay(true) {
                            warn!(%err, "failed to set TCP_NODELAY");
                        }
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
                        let pipeline = pipeline.clone();
                        let pool = pool.clone();
                        tokio::spawn(async move {
                            let _permit = permit;
                            serve_connection(stream, client, pipeline, Transport::Tcp, pool).await;
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

/// Per-message read window: the length prefix and the message body must both
/// arrive inside the same window, so a client cannot hold a connection (and
/// its permit) indefinitely by dripping bytes across two separate timeouts.
const READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Write window for one response. A client that receives but never ACKs can
/// otherwise park the write forever while holding its connection permit.
const WRITE_TIMEOUT: Duration = Duration::from_secs(30);
/// Maximum message that fits a 2-byte length prefix.
const MAX_TCP_MESSAGE: usize = u16::MAX as usize;

/// Write a 2-byte length prefix followed by `body` as two vectored slices.
///
/// The response is written straight from the pipeline's buffer instead of
/// being copied into a fixed-size frame buffer, so a message at the protocol
/// maximum is framable without extra capacity.
///
/// # Arguments
///
/// * `stream` - Destination stream
/// * `prefix` - Big-endian message length
/// * `body` - Encoded DNS message
///
/// # Errors
///
/// Returns an error when the stream fails or accepts zero bytes.
async fn write_framed<W>(stream: &mut W, prefix: [u8; 2], body: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut bufs = [IoSlice::new(&prefix), IoSlice::new(body)];
    let mut remaining: &mut [IoSlice<'_>] = &mut bufs;
    while !remaining.is_empty() {
        let written = stream.write_vectored(remaining).await?;
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }
        IoSlice::advance_slices(&mut remaining, written);
    }
    Ok(())
}

/// Serve length-prefixed DNS messages on one connection until it closes.
pub async fn serve_connection<S>(
    mut stream: S,
    client: SocketAddr,
    pipeline: PipelineHandle,
    transport: Transport,
    pool: BufferPool,
) where
    S: AsyncRead + AsyncWrite + Unpin + Probe,
{
    loop {
        // One pooled buffer per message, released back to the pool when this
        // iteration ends or the connection returns early.
        let mut buf = pool.get();
        // One deadline covers the whole message: length prefix + body.
        let len = match tokio::time::timeout(READ_TIMEOUT, async {
            let mut lenbuf = [0u8; 2];
            stream.read_exact(&mut lenbuf).await?;
            let len = usize::from(u16::from_be_bytes(lenbuf));
            if len > 0 {
                stream.read_exact(&mut buf[0..len]).await?;
            }
            Ok::<usize, std::io::Error>(len)
        })
        .await
        {
            Ok(Ok(len)) => len,
            Ok(Err(_)) => break,
            Err(_) => break,
        };
        if len == 0 {
            break;
        }

        // While the query resolves, watch the socket without consuming data.
        // EOF means the client is gone, so the upstream subquery tree can be
        // dropped. A readable socket means the client pipelined another query;
        // in that case stop probing and let the current query finish.
        let cancel = CancellationToken::new();
        let mut handle =
            Box::pin(pipeline.handle_with_cancel(&buf[..len], client, transport, cancel.clone()));
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
        if response.len() > MAX_TCP_MESSAGE {
            // A message larger than a 2-byte length prefix cannot be framed.
            // Send a TC-marked question-only stub so the client retries via a
            // transport that handles the answer, instead of desyncing the
            // stream when the tail is re-read as a new length prefix.
            debug!(%client, "response exceeds the TCP message limit");
            let truncation = match decode(&response) {
                Ok(mut message) => {
                    message.answers.clear();
                    message.authorities.clear();
                    message.additionals.clear();
                    message.metadata.truncation = true;
                    encode(&message).ok()
                }
                Err(_) => None,
            };
            let Some(truncation) = truncation else { break };
            let Ok(length) = u16::try_from(truncation.len()) else {
                break;
            };
            if tokio::time::timeout(
                WRITE_TIMEOUT,
                write_framed(&mut stream, length.to_be_bytes(), &truncation),
            )
            .await
            .is_err()
            {
                debug!(%client, "TCP write timed out");
            }
            break;
        }
        let Ok(length) = u16::try_from(response.len()) else {
            break;
        };
        if tokio::time::timeout(
            WRITE_TIMEOUT,
            write_framed(&mut stream, length.to_be_bytes(), &response),
        )
        .await
        .is_err()
        {
            debug!(%client, "TCP write timed out");
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    use super::{Probe, write_framed};

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

    #[tokio::test]
    async fn write_framed_accepts_a_full_size_message() {
        let body = vec![0xABu8; u16::MAX as usize];
        let mut out = Vec::new();

        write_framed(&mut out, 0x1234u16.to_be_bytes(), &body)
            .await
            .expect("write");

        assert_eq!(out.len(), 2 + body.len());
        assert_eq!(&out[..2], &[0x12, 0x34]);
        assert_eq!(&out[2..], body.as_slice());
    }

    #[tokio::test]
    async fn write_framed_retries_partial_writes() {
        let body: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let mut writer = ChunkedWriter {
            written: Vec::new(),
            max_per_write: 7,
        };

        write_framed(&mut writer, [0x00, 0x2A], &body)
            .await
            .expect("write");

        assert_eq!(writer.written.len(), 2 + body.len());
        assert_eq!(&writer.written[..2], &[0x00, 0x2A]);
        assert_eq!(&writer.written[2..], body.as_slice());
    }

    /// Writer that accepts at most `max_per_write` bytes per call, so the
    /// vectored loop has to advance through partially written slices.
    struct ChunkedWriter {
        written: Vec<u8>,
        max_per_write: usize,
    }

    impl AsyncWrite for ChunkedWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let take = buf.len().min(self.max_per_write);
            self.written.extend_from_slice(&buf[..take]);
            Poll::Ready(Ok(take))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
}
