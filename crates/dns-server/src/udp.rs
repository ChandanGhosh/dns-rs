use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;

use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use tracing::warn;

use crate::phase::{Phase, PhaseTimer};
use crate::pipeline::{Prepared, QueryPipeline, Transport};

/// Largest possible DNS message; matches `dns_proto`'s buffer pool size.
const MAX_DATAGRAM: usize = 65_535;

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
    // One scratch datagram per receive loop. Dispatch is fully synchronous
    // (a hit is answered before this loop iterates) or hands the query to a
    // task that owns its own state, so the buffer is never shared with a task
    // and the next receive can reuse it.
    let mut query = vec![0_u8; MAX_DATAGRAM];

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            result = socket.recv_from(&mut query) => {
                match result {
                    Ok((len, client)) => {
                        // The queue timer spans the gap between the receive
                        // syscall and handling starting. The hit path runs
                        // inline in this loop, so the gap is now just this
                        // dispatch; a miss spawns, and its second span covers
                        // the task's scheduling wait.
                        let queue = PhaseTimer::start(Phase::Queue);
                        queue.end();
                        let prepared = pipeline.prepare(
                            &query[..len],
                            client,
                            Transport::Udp,
                            CancellationToken::new(),
                        );
                        match prepared {
                            Prepared::Answer(response) => {
                                if let Some(response) = response {
                                    let send = PhaseTimer::start(Phase::Send);
                                    if let Err(error) = socket.try_send_to(&response, client)
                                        && error.kind() == ErrorKind::WouldBlock
                                    {
                                        // Send buffer full: hand the reply to a
                                        // task that can wait for room rather
                                        // than stall the receive loop.
                                        let socket = Arc::clone(&socket);
                                        tokio::spawn(async move {
                                            let _ = socket.send_to(&response, client).await;
                                        });
                                    }
                                    send.end();
                                }
                            }
                            Prepared::Resolve(job) => {
                                // Upstream work may not finish for a long
                                // time, so it gets its own task; spawning a
                                // task per query is what this loop no longer
                                // does on the hit path.
                                let dispatch = PhaseTimer::start(Phase::Queue);
                                let socket = Arc::clone(&socket);
                                tokio::spawn(async move {
                                    dispatch.end();
                                    if let Some(response) = job.run().await {
                                        let send = PhaseTimer::start(Phase::Send);
                                        let _ = socket.send_to(&response, client).await;
                                        send.end();
                                    }
                                });
                            }
                        }
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
