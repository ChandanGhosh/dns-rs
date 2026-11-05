//! Batched datagram sends through `sendmmsg(2)` (Linux only).
//!
//! The UDP receive loop may produce several immediate replies (cache hits and
//! short-circuit answers) while draining one `recvmmsg(2)` harvest. Sending
//! them with a single `sendmmsg(2)` reduces per-reply syscall overhead while
//! preserving per-destination addressing.

#![allow(unsafe_code)]

use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};

use socket2::SockAddr;
use tokio::net::UdpSocket;

/// Send `messages` as datagrams in as few `sendmmsg(2)` calls as possible.
///
/// Each entry is `(payload, destination)`. The call is non-blocking
/// (`MSG_DONTWAIT`). If the socket would block after sending some messages,
/// `Ok(sent)` returns the number successfully handed to the kernel; the
/// caller should deliver the remainder asynchronously to avoid stalling the
/// receive loop.
///
/// # Errors
///
/// Returns an I/O error when no messages were sent and the socket reported a
/// failure other than `WouldBlock`/`Interrupted`.
pub(crate) fn send_batch(
    socket: &UdpSocket,
    messages: &[(&[u8], SocketAddr)],
) -> io::Result<usize> {
    if messages.is_empty() {
        return Ok(0);
    }
    send_raw(socket.as_raw_fd(), messages)
}

fn empty_header() -> libc::msghdr {
    // SAFETY: all-zero is a valid `msghdr` bit pattern (null pointers, zero
    // lengths); every field used by `sendmmsg` is set explicitly below.
    unsafe { std::mem::zeroed() }
}

fn send_raw(fd: RawFd, messages: &[(&[u8], SocketAddr)]) -> io::Result<usize> {
    // `SockAddr` (socket2) keeps `sockaddr_storage`-sized data with a length.
    // Build owned address/storage and iovecs that live for the duration of the syscall.
    let mut addrs: Vec<SockAddr> = Vec::with_capacity(messages.len());
    let mut iovecs: Vec<libc::iovec> = Vec::with_capacity(messages.len());
    let mut hdrs: Vec<libc::mmsghdr> = Vec::with_capacity(messages.len());

    for (payload, dest) in messages {
        addrs.push(SockAddr::from(*dest));
        iovecs.push(libc::iovec {
            iov_base: payload.as_ptr() as *mut libc::c_void,
            iov_len: payload.len(),
        });
    }

    // Build headers after vectors are populated so pointers remain stable
    // (we don't mutate/resize these vectors again).
    for index in 0..messages.len() {
        let mut header = empty_header();
        header.msg_name = addrs[index].as_ptr() as *mut libc::c_void;
        header.msg_namelen = addrs[index].len();
        header.msg_iov = &raw mut iovecs[index];
        header.msg_iovlen = 1;
        hdrs.push(libc::mmsghdr {
            msg_hdr: header,
            msg_len: 0,
        });
    }

    let mut sent_total = 0usize;
    while sent_total < hdrs.len() {
        // SAFETY: `hdrs`, `iovecs`, and `addrs` are live for this call;
        // iovecs point into `messages` payload slices borrowed for the call;
        // `fd` is valid for the borrowed socket. `MSG_DONTWAIT` prevents
        // blocking in the receive loop's context.
        let rc = unsafe {
            libc::sendmmsg(
                fd,
                hdrs[sent_total..].as_mut_ptr(),
                (hdrs.len() - sent_total) as _,
                libc::MSG_DONTWAIT as _,
            )
        };
        if rc > 0 {
            sent_total += rc as usize;
            continue;
        }
        if rc == 0 {
            // No messages sent; treat as would-block so caller can fall back.
            if sent_total == 0 {
                return Err(ErrorKind::WouldBlock.into());
            }
            return Ok(sent_total);
        }
        let err = io::Error::last_os_error();
        if err.kind() == ErrorKind::Interrupted {
            continue;
        }
        if err.kind() == ErrorKind::WouldBlock {
            return Ok(sent_total);
        }
        if sent_total == 0 {
            return Err(err);
        }
        // Some messages were sent before an error; report partial progress.
        return Ok(sent_total);
    }

    Ok(sent_total)
}

#[cfg(test)]
mod tests {
    use super::send_batch;
    use std::collections::BTreeSet;
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn sends_multiple_datagrams() {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind receiver");
        let sender = UdpSocket::bind("127.0.0.1:0").await.expect("bind sender");
        let dest: SocketAddr = receiver.local_addr().expect("dest");
        let messages: Vec<(&[u8], SocketAddr)> =
            vec![(b"one".as_ref(), dest), (b"two".as_ref(), dest)];

        let sent = send_batch(&sender, &messages).expect("send");
        assert_eq!(sent, 2);

        let mut received = BTreeSet::new();
        for _ in 0..2 {
            let mut buf = [0u8; 16];
            let (n, _) = receiver.recv_from(&mut buf).await.expect("recv");
            received.insert(buf[..n].to_vec());
        }
        assert_eq!(received, BTreeSet::from([b"one".to_vec(), b"two".to_vec()]));
    }
}
