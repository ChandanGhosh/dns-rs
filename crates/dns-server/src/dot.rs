//! DNS-over-TLS listener (RFC 7858).

use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::pipeline::{QueryPipeline, Transport};
use crate::tcp;

pub async fn run(
    listener: TcpListener,
    acceptor: TlsAcceptor,
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
                        if let Err(err) = stream.set_nodelay(true) {
                            warn!(%err, "failed to set TCP_NODELAY");
                        }
                        let permit = tokio::select! {
                            _ = shutdown.cancelled() => break,
                            permit = Arc::clone(&connections).acquire_owned() => {
                                match permit {
                                    Ok(permit) => permit,
                                    Err(_) => break,
                                }
                            }
                        };
                        let acceptor = acceptor.clone();
                        let pipeline = Arc::clone(&pipeline);
                        tokio::spawn(async move {
                            let _permit = permit;
                            let stream = match tokio::time::timeout(
                                Duration::from_secs(10),
                                acceptor.accept(stream),
                            )
                            .await
                            {
                                Ok(Ok(stream)) => stream,
                                Ok(Err(error)) => {
                                    debug!(%client, %error, "DoT handshake failed");
                                    return;
                                }
                                Err(_) => {
                                    debug!(%client, "DoT handshake timed out");
                                    return;
                                }
                            };
                            tcp::serve_connection(stream, client, pipeline, Transport::Tls).await;
                        });
                    }
                    Err(error) => {
                        debug!(%error, "DoT accept error");
                    }
                }
            }
        }
    }
    Ok(())
}
