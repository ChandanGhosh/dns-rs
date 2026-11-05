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
pub(crate) const MAX_DATAGRAM: usize = 65_535;

pub fn bind(
    addr: SocketAddr,
    recv_buffer_size: usize,
    send_buffer_size: usize,
) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(unix)]
    socket.set_reuse_port(true)?;
    if recv_buffer_size > 0
        && let Err(err) = socket.set_recv_buffer_size(recv_buffer_size)
    {
        warn!(%err, "failed to set UDP receive buffer size");
    }
    if send_buffer_size > 0
        && let Err(err) = socket.set_send_buffer_size(send_buffer_size)
    {
        warn!(%err, "failed to set UDP send buffer size");
    }
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}

/// Receive, dispatch, and answer UDP datagrams until `shutdown` fires.
///
/// # Arguments
///
/// * `socket` - the bound UDP socket this worker owns
/// * `pipeline` - query pipeline shared with every other listener
/// * `shutdown` - cancellation token that stops the receive loop
///
/// # Returns
///
/// `Ok` once the loop has stopped and in-flight replies had a moment to
/// flush; listener errors are reported as `Err`
pub async fn run(
    socket: UdpSocket,
    pipeline: Arc<QueryPipeline>,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    let socket = Arc::new(socket);
    receive_loop(&socket, &pipeline, shutdown).await?;

    // Give in-flight query tasks a moment to finish sending responses.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    Ok(())
}

/// Drain the socket until `shutdown` fires, dispatching each datagram.
///
/// On Linux every receive harvests up to `recv_batch::BATCH` datagrams in
/// one `recvmmsg(2)` syscall; other targets fall back to one
/// `recvfrom(2)` per datagram. Either way the dispatch is synchronous in
/// this loop: cache hits and short-circuit replies are answered inline,
/// and only resolutions that may wait on upstreams spawn a task.
#[cfg(target_os = "linux")]
async fn receive_loop(
    socket: &Arc<UdpSocket>,
    pipeline: &Arc<QueryPipeline>,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
    let mut batch = crate::recv_batch::RecvBatch::new();

    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            result = batch.recv(socket) => {
                match result {
                    Ok(count) => {
                        // The queue timer spans the gap between the receive
                        // syscall and handling starting. One timer is opened
                        // per batch and ended once per message, so each
                        // query records its own wait, including its position
                        // behind the messages dispatched before it.
                        let queue = PhaseTimer::start(Phase::Queue);
                        for index in 0..count {
                            let Some((client, query)) = batch.message(index) else {
                                continue;
                            };
                            queue.end();
                            dispatch(socket, pipeline, query, client);
                        }
                    }
                    Err(err) => {
                        debug!(%err, "UDP recv error");
                    }
                }
            }
        }
    }

    Ok(())
}

/// Portable receive path: one `recvfrom(2)` syscall per datagram.
#[cfg(not(target_os = "linux"))]
async fn receive_loop(
    socket: &Arc<UdpSocket>,
    pipeline: &Arc<QueryPipeline>,
    shutdown: CancellationToken,
) -> std::io::Result<()> {
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
                        let queue = PhaseTimer::start(Phase::Queue);
                        queue.end();
                        dispatch(socket, pipeline, &query[..len], client);
                    }
                    Err(err) => {
                        debug!(%err, "UDP recv error");
                    }
                }
            }
        }
    }

    Ok(())
}

/// Run one received datagram through the pipeline to completion.
///
/// The caller must have ended the receive-side `Phase::Queue` timer, and
/// `query` must borrow no state that outlives this call: both reply kinds
/// either send here or move into a task that owns everything it needs.
fn dispatch(socket: &Arc<UdpSocket>, pipeline: &QueryPipeline, query: &[u8], client: SocketAddr) {
    let prepared = pipeline.prepare(query, client, Transport::Udp, CancellationToken::new());
    match prepared {
        Prepared::Answer(response) => {
            if let Some(response) = response {
                let send = PhaseTimer::start(Phase::Send);
                if let Err(error) = socket.try_send_to(&response, client)
                    && error.kind() == ErrorKind::WouldBlock
                {
                    // Send buffer full: hand the reply to a task that can wait
                    // for room rather than stall the receive loop.
                    let socket = Arc::clone(socket);
                    tokio::spawn(async move {
                        let _ = socket.send_to(&response, client).await;
                    });
                }
                send.end();
            }
        }
        Prepared::Resolve(job) => {
            // Upstream work may not finish for a long time, so it gets its
            // own task; spawning a task per query is what this loop no longer
            // does on the hit path.
            let queued = PhaseTimer::start(Phase::Queue);
            let socket = Arc::clone(socket);
            tokio::spawn(async move {
                queued.end();
                if let Some(response) = job.run().await {
                    let send = PhaseTimer::start(Phase::Send);
                    let _ = socket.send_to(&response, client).await;
                    send.end();
                }
            });
        }
    }
}
