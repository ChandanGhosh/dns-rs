use std::net::SocketAddr;
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::debug;

use crate::pipeline::{QueryPipeline, Transport};

pub fn bind(addr: SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
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
    let mut buf = vec![0u8; 65_535];

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok((len, client)) => {
                        // Handle each datagram in its own task so a slow
                        // upstream cannot block the receive loop.
                        let socket = Arc::clone(&socket);
                        let pipeline = Arc::clone(&pipeline);
                        let query = buf[..len].to_vec();
                        tokio::spawn(async move {
                            if let Some(response) =
                                pipeline.handle(&query, client, Transport::Udp).await
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
