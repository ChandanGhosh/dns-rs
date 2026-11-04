//! Batched datagram receives through `recvmmsg(2)` (Linux only).
//!
//! One receive syscall harvests up to [`BATCH`] datagrams into scratch
//! state owned by [`RecvBatch`] instead of paying one `recvfrom(2)` per
//! query. The message headers, iovecs, and source-address slots are
//! initialized once when the batch is created and reused by every call,
//! so the receive path performs no per-query allocation and no per-call
//! scratch rebuild.
//!
//! This module is the crate's syscall boundary, so it carries the
//! module-wide `#![allow(unsafe_code)]` (the workspace only warns on
//! `unsafe`). Each `unsafe` block is a raw call or the construction of
//! the buffers it consumes, and every one documents its invariants in a
//! `SAFETY` comment.

#![allow(unsafe_code)]

use std::array;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::ptr;

use socket2::{SockAddr, SockAddrStorage};
use tokio::io::Interest;
use tokio::net::UdpSocket;

use crate::udp::MAX_DATAGRAM;

/// Datagrams one `recvmmsg(2)` call may harvest.
///
/// Eight slots cover a typical loopback burst while costing well under a
/// kilobyte of scratch state per worker; the kernel returns whatever has
/// already arrived, so a quiet socket still pays one non-blocking syscall
/// and never waits for a full batch.
const BATCH: usize = 8;

/// Reusable scratch buffers and message headers for one receive loop.
pub(crate) struct RecvBatch {
    /// `BATCH` contiguous datagram slots, reused across receives.
    datagrams: Box<[u8]>,
    /// Message headers and address slots. Boxed because the batch stores
    /// raw pointers into them: boxing fixes their addresses, so moving
    /// the `RecvBatch` value can never invalidate the headers.
    slots: Box<Slots>,
}

/// The `mmsghdr`/`iovec`/address state one `recvmmsg(2)` call consumes.
struct Slots {
    /// One iovec per slot, pointing into `RecvBatch::datagrams`.
    iovecs: [libc::iovec; BATCH],
    /// Kernel-written source address per slot.
    names: [SockAddrStorage; BATCH],
    /// The `mmsghdr` array `recvmmsg(2)` fills in.
    messages: [libc::mmsghdr; BATCH],
}

// SAFETY: the raw pointers in `slots.messages`/`slots.iovecs` address the
// `datagrams` allocation and the fields of the boxed `slots`, all of which
// move with the batch value; no other thread observes them, and they are
// only ever dereferenced by the kernel during a `recv_raw` call on the
// thread that owns this value. Transferring that ownership is sound.
unsafe impl Send for RecvBatch {}

/// A zeroed message header, ready for [`RecvBatch::init_headers`] to point
/// at the batch's buffers.
///
/// `libc::msghdr` hides padding fields on some targets (musl's `__pad1`/
/// `__pad2`), so it cannot be built with struct-literal syntax everywhere
/// this crate compiles. Zeroing first and then assigning the public fields
/// is portable across gnu and musl.
fn empty_header() -> libc::msghdr {
    // SAFETY: every `msghdr` field is a raw pointer, an integer, or (on
    // musl) `MaybeUninit` padding, so the all-zero bit pattern - null
    // pointers and zero lengths - is valid on every supported target, and
    // each field the receive path relies on is overwritten with an
    // explicit value before the kernel sees the header.
    unsafe { std::mem::zeroed() }
}

impl RecvBatch {
    /// Allocate and initialize the scratch state for one socket's receive
    /// loop.
    pub(crate) fn new() -> Self {
        let mut batch = Self {
            datagrams: vec![0_u8; BATCH * MAX_DATAGRAM].into_boxed_slice(),
            slots: Box::new(Slots {
                iovecs: array::from_fn(|_| libc::iovec {
                    iov_base: ptr::null_mut(),
                    iov_len: 0,
                }),
                names: array::from_fn(|_| SockAddrStorage::zeroed()),
                messages: array::from_fn(|_| libc::mmsghdr {
                    msg_hdr: empty_header(),
                    msg_len: 0,
                }),
            }),
        };
        batch.init_headers();
        batch
    }

    /// Harvest the datagrams currently queued on `socket`.
    ///
    /// Awaits readability, then fills slots `0..n` in one `recvmmsg(2)`
    /// call and returns `n`. A `WouldBlock` from the syscall is absorbed
    /// here: the readiness wait re-arms and the future pends until a
    /// datagram actually arrives, so callers only see `Ok(n >= 1)` or a
    /// genuine error.
    ///
    /// # Arguments
    ///
    /// * `socket` - the non-blocking UDP socket to receive from
    ///
    /// # Returns
    ///
    /// Number of slots filled; read them with [`RecvBatch::message`]
    pub(crate) async fn recv(&mut self, socket: &UdpSocket) -> io::Result<usize> {
        socket
            .async_io(Interest::READABLE, || self.recv_raw(socket.as_raw_fd()))
            .await
    }

    /// The source address and payload of the datagram in slot `index`.
    ///
    /// Returns `None` when the kernel reported no usable source address;
    /// an unanswerable datagram is dropped either way.
    pub(crate) fn message(&self, index: usize) -> Option<(SocketAddr, &[u8])> {
        debug_assert!(index < BATCH);
        let len = self.slots.messages[index].msg_len as usize;
        debug_assert!(len <= MAX_DATAGRAM);
        // SAFETY: the kernel wrote `msg_namelen` bytes of a datagram source
        // address into this slot during the last `recv`. `SockAddrStorage`
        // is a transparent wrapper over `sockaddr_storage` whose fields are
        // integers and bytes, so every bit pattern in it is valid; copying
        // it out of `&self` is race-free because no receive is in flight
        // while the receive loop reads slots.
        let storage = unsafe { ptr::read(&self.slots.names[index]) };
        // SAFETY: `msg_namelen` was written by the same receive, is at most
        // `size_of::<SockAddrStorage>()`, and for a UDP datagram the kernel
        // only writes a complete `sockaddr_in`/`sockaddr_in6`, satisfying
        // `SockAddr::new`'s family/length contract.
        let address =
            unsafe { SockAddr::new(storage, self.slots.messages[index].msg_hdr.msg_namelen) };
        let client = address.as_socket()?;
        let start = index * MAX_DATAGRAM;
        Some((client, &self.datagrams[start..start + len]))
    }

    /// Issue one non-blocking `recvmmsg(2)`, retrying on interruption.
    ///
    /// # Arguments
    ///
    /// * `fd` - descriptor of the UDP socket `self` was readied against
    ///
    /// # Returns
    ///
    /// Number of datagrams written into the slots (`>= 1`), or
    /// [`ErrorKind::WouldBlock`] when the socket held nothing to harvest
    fn recv_raw(&mut self, fd: RawFd) -> io::Result<usize> {
        loop {
            // SAFETY: the boxed `slots` header state and the `datagrams`
            // allocation are owned buffers of `self`, mutably borrowed for
            // the duration of this call, so every pointer the kernel
            // follows (message headers, iovec bases, name slots) is
            // aligned, initialized, and alive until `recvmmsg(2)` returns;
            // `fd` belongs to the `UdpSocket` borrowed in `recv` and
            // outlives the call. `MSG_DONTWAIT` guarantees the syscall
            // never blocks, which is what makes it legal inside Tokio's
            // readiness callback.
            let received = unsafe {
                libc::recvmmsg(
                    fd,
                    self.slots.messages.as_mut_ptr(),
                    BATCH as _,
                    libc::MSG_DONTWAIT as _,
                    ptr::null_mut(),
                )
            };

            if received > 0 {
                return Ok(received as usize);
            }
            if received == 0 {
                // No datagram was written: report not-ready so the caller's
                // readiness wait re-arms instead of spinning on a stale flag.
                return Err(ErrorKind::WouldBlock.into());
            }

            let error = io::Error::last_os_error();
            if error.kind() != ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    /// Point every message header at this batch's scratch buffers, once.
    ///
    /// The headers are never rebuilt: Linux `recvmsg`/`recvmmsg` do not
    /// write back into userspace iovec structs or message headers, so the
    /// only fields the receive path reads - `msg_len`, `msg_flags`,
    /// `msg_namelen`, and the name bytes - are filled fresh by each call
    /// for the slots `0..n` it actually received, and slots outside that
    /// range are never read. `msg_namelen` starts at the full storage
    /// size (the capacity the kernel requires on input) and afterwards
    /// holds the address size of this socket's family (16 for `AF_INET`,
    /// 28 for `AF_INET6`), which never shrinks below what the same
    /// socket's family needs. The `slots` box fixes the arrays' addresses,
    /// so one-time initialization stays valid no matter how the batch
    /// value moves. Forming the raw pointers is safe without a borrow:
    /// they are dereferenced only inside `recvmmsg(2)` while the
    /// `&mut self` borrow in [`RecvBatch::recv_raw`] is live.
    fn init_headers(&mut self) {
        for index in 0..BATCH {
            let offset = index * MAX_DATAGRAM;
            self.slots.iovecs[index] = libc::iovec {
                // SAFETY: `offset + MAX_DATAGRAM` equals the allocation's
                // length on the last slot and is smaller on the rest, so
                // the offset stays in bounds; the pointer is only handed
                // to the kernel inside `recv_raw` while `self` is borrowed.
                iov_base: unsafe { self.datagrams.as_mut_ptr().add(offset) }.cast(),
                iov_len: MAX_DATAGRAM,
            };
            self.slots.names[index] = SockAddrStorage::zeroed();
            let mut header = empty_header();
            header.msg_name = (&raw mut self.slots.names[index]).cast();
            header.msg_namelen = self.slots.names[index].size_of();
            header.msg_iov = &raw mut self.slots.iovecs[index];
            header.msg_iovlen = 1;
            self.slots.messages[index] = libc::mmsghdr {
                msg_hdr: header,
                msg_len: 0,
            };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BATCH, RecvBatch};
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::net::UdpSocket;

    /// A loopback receiver and a datagram sender with the sender's address.
    async fn sockets() -> (UdpSocket, std::net::UdpSocket, SocketAddr) {
        let receiver = UdpSocket::bind("127.0.0.1:0").await.expect("bind receiver");
        let sender = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind sender");
        let from = sender.local_addr().expect("sender address");
        (receiver, sender, from)
    }

    /// Every slot harvested from `count` messages, checked against the
    /// sender's address.
    fn collect(batch: &RecvBatch, count: usize, from: SocketAddr) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| {
                let (client, payload) = batch.message(index).expect("source address");
                assert_eq!(client, from, "every slot keeps the sender's address");
                payload.to_vec()
            })
            .collect()
    }

    /// One datagram keeps its source address and payload through the batch
    /// path exactly as a single `recvfrom` would.
    #[tokio::test]
    async fn harvests_a_single_datagram_intact() {
        let (receiver, sender, from) = sockets().await;
        let mut batch = RecvBatch::new();
        let to = receiver.local_addr().expect("receiver address");
        sender.send_to(b"ping", to).expect("send");

        let count = batch.recv(&receiver).await.expect("harvest");
        assert_eq!(count, 1);
        let (client, payload) = batch.message(0).expect("message");
        assert_eq!(client, from);
        assert_eq!(payload, b"ping");
    }

    /// A backlog larger than one batch drains across calls with no datagram
    /// lost: the first call fills all slots, the tail waits for the next.
    #[tokio::test]
    async fn drains_a_backlog_across_calls() {
        let (receiver, sender, from) = sockets().await;
        let mut batch = RecvBatch::new();
        let to = receiver.local_addr().expect("receiver address");
        let total = BATCH + 4;
        for index in 0..total {
            sender
                .send_to(format!("q{index}").as_bytes(), to)
                .expect("send");
        }

        let first = batch.recv(&receiver).await.expect("first harvest");
        assert_eq!(first, BATCH, "one syscall fills every slot");
        let mut seen = collect(&batch, first, from);

        let second = batch.recv(&receiver).await.expect("second harvest");
        assert_eq!(second, total - BATCH, "the tail waits for the next call");
        seen.extend(collect(&batch, second, from));

        seen.sort();
        let mut expected: Vec<Vec<u8>> = (0..total)
            .map(|index| format!("q{index}").into_bytes())
            .collect();
        expected.sort();
        assert_eq!(seen, expected, "no datagram is lost or altered");
    }

    /// After a harvest drains the socket, the next receive waits instead
    /// of spinning on a stale readiness flag or leaking `WouldBlock` to
    /// the receive loop.
    #[tokio::test]
    async fn waits_when_the_socket_is_drained() {
        let (receiver, sender, _from) = sockets().await;
        let mut batch = RecvBatch::new();
        let to = receiver.local_addr().expect("receiver address");
        sender.send_to(b"ping", to).expect("send");
        assert_eq!(batch.recv(&receiver).await.expect("harvest"), 1);

        let idle = tokio::time::timeout(Duration::from_millis(20), batch.recv(&receiver)).await;
        assert!(idle.is_err(), "a drained socket must pend, got {idle:?}");
    }
}
