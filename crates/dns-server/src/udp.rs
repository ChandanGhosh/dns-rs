use std::net::SocketAddr;
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use tracing::warn;

use crate::pipeline::{QueryPipeline, Transport};
use dns_proto::buffer_pool::BufferPool;

pub fn bind(addr: SocketAddr, recv_buffer_size: usize) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    if recv_buffer_size > 0
        && let Err(err) = socket.set_recv_buffer_size(recv_buffer_size)
    {
        warn!(%err, "failed to set UDP receive buffer size");
    }
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

pub async fn run(
    socket: UdpSocket,
    pipeline: Arc<QueryPipeline>,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    let socket = Arc::new(socket);
    let pool = BufferPool::default();

    loop {
        // Receive straight into a pooled buffer: the datagram is moved into
        // the query task without a copy, and the task returns the buffer to
        // the pool when it drops `query`.
        let mut query = pool.get();
        tokio::select! {
            _ = shutdown.cancelled() => break,
            result = socket.recv_from(&mut query) => {
                match result {
                    Ok((len, client)) => {
                        // Handle each datagram in its own task so a slow
                        // upstream cannot block the receive loop.
                        let socket = Arc::clone(&socket);
                        let pipeline = Arc::clone(&pipeline);
                        tokio::spawn(async move {
                            if let Some(response) =
                                pipeline.handle(&query[..len], client, Transport::Udp).await
                            {
                                let _ = socket.send_to(&response, client).await;
                            }
                        });
                    }
                    Err(err) => {
                        debug!(%err, "UDP recv error");
                    }
                }
            }
        }
    }

    // Give in-flight query tasks a moment to finish sending responses.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    Ok(())
}
