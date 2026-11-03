//! Reusable DNS message buffers.
//!
//! Allocating a fresh `Vec<u8>` for every query takes the allocator lock on the
//! hot path. [`BufferPool`] hands out [`PooledBuffer`]s that return their
//! allocation to the pool when dropped, so steady-state traffic reuses the same
//! memory. The RAII wrapper also covers early returns and panics, which manual
//! put-back calls tend to miss.

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

/// Largest possible DNS message, and therefore the receive buffer size.
const BUFFER_SIZE: usize = 65_535;
/// Buffers kept for reuse per pool.
const MAX_CAPACITY: usize = 256;

/// A pool of reusable message buffers.
///
/// Cloning shares the same pool; listeners and upstream clients each own one
/// pool, and the clones handed to connection tasks and replies all return
/// buffers to it.
#[derive(Clone)]
pub struct BufferPool {
    inner: Arc<PoolInner>,
}

struct PoolInner {
    free: Mutex<Vec<Vec<u8>>>,
    buffer_size: usize,
    max_capacity: usize,
}

impl BufferPool {
    /// Create a pool that hands out buffers of `buffer_size` bytes and keeps at
    /// most `max_capacity` of them for reuse.
    pub fn new(buffer_size: usize, max_capacity: usize) -> Self {
        Self {
            inner: Arc::new(PoolInner {
                free: Mutex::new(Vec::with_capacity(max_capacity)),
                buffer_size,
                max_capacity,
            }),
        }
    }

    /// Take a buffer from the pool, allocating one if the pool is empty.
    ///
    /// The buffer returns to the pool when the [`PooledBuffer`] is dropped.
    pub fn get(&self) -> PooledBuffer {
        let mut free = self
            .inner
            .free
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let mut buf = free.pop().unwrap_or_default();
        drop(free);
        // Buffers are kept at full length, so this only runs for a fresh
        // allocation and never zero-fills a recycled buffer.
        if buf.len() != self.inner.buffer_size {
            buf.resize(self.inner.buffer_size, 0);
        }
        PooledBuffer {
            pool: self.clone(),
            buf,
        }
    }

    /// Return `buf` to the pool unless it was resized or the pool is full.
    fn release(&self, buf: Vec<u8>) {
        if buf.len() != self.inner.buffer_size {
            return;
        }
        let mut free = self
            .inner
            .free
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if free.len() < self.inner.max_capacity {
            free.push(buf);
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self::new(BUFFER_SIZE, MAX_CAPACITY)
    }
}

/// Report the pool's sizing and free count; buffered bytes are never dumped.
impl fmt::Debug for BufferPool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let free = self
            .inner
            .free
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .len();
        formatter
            .debug_struct("BufferPool")
            .field("buffer_size", &self.inner.buffer_size)
            .field("max_capacity", &self.inner.max_capacity)
            .field("free", &free)
            .finish()
    }
}

/// A buffer borrowed from a [`BufferPool`].
///
/// Returns its allocation to the pool on drop, including on early returns and
/// panics, so callers never put buffers back by hand.
pub struct PooledBuffer {
    pool: BufferPool,
    buf: Vec<u8>,
}

impl Deref for PooledBuffer {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.buf
    }
}

impl DerefMut for PooledBuffer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.buf
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        self.pool.release(std::mem::take(&mut self.buf));
    }
}

/// A received DNS datagram backed by a pooled buffer.
///
/// Derefs to exactly the bytes that were received; the underlying allocation
/// stays at full length so dropping the reply returns it to the pool. Decode
/// (or otherwise consume) the reply before letting it go out of scope, since
/// its bytes may be handed to another exchange once it is dropped.
pub struct PooledReply {
    buf: PooledBuffer,
    len: usize,
}

impl PooledReply {
    /// Wrap `buf` as a datagram of `len` received bytes.
    ///
    /// # Arguments
    ///
    /// * `buf` - Pooled buffer the datagram was received into
    /// * `len` - Number of bytes received, clamped to the buffer's length
    pub fn new(buf: PooledBuffer, len: usize) -> Self {
        Self {
            len: len.min(buf.len()),
            buf,
        }
    }
}

impl Deref for PooledReply {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buf[..self.len]
    }
}

/// Print only the received length; the full 64 KiB buffer is never dumped.
impl fmt::Debug for PooledReply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PooledReply")
            .field("len", &self.len)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recycled_buffer_reuses_the_same_allocation() {
        let pool = BufferPool::new(512, 4);
        let first = pool.get();
        let addr = first.as_ptr();
        assert_eq!(first.len(), 512);
        drop(first);

        let second = pool.get();
        assert_eq!(second.as_ptr(), addr);
    }

    #[test]
    fn pool_caps_the_number_of_recycled_buffers() {
        let pool = BufferPool::new(64, 2);
        let buffers: Vec<_> = (0..5).map(|_| pool.get()).collect();
        drop(buffers);
        assert_eq!(pool.inner.free.lock().expect("lock").len(), 2);
    }

    #[test]
    fn resized_buffers_are_not_recycled() {
        let pool = BufferPool::new(64, 2);
        let mut buf = pool.get();
        buf.truncate(8);
        drop(buf);
        assert!(pool.inner.free.lock().expect("lock").is_empty());
    }

    #[test]
    fn reply_exposes_only_received_bytes_and_recycles() {
        let pool = BufferPool::new(64, 1);
        let mut buf = pool.get();
        buf[..4].copy_from_slice(&[9, 8, 7, 6]);
        let addr = buf.as_ptr();
        let reply = PooledReply::new(buf, 4);

        assert_eq!(&reply[..], &[9, 8, 7, 6][..]);
        assert_eq!(reply.len(), 4);

        drop(reply);
        let recycled = pool.get();
        assert_eq!(
            recycled.as_ptr(),
            addr,
            "the reply's buffer must return to the pool on drop"
        );
    }

    #[test]
    fn reply_debug_reports_only_the_length() {
        let pool = BufferPool::new(64, 1);
        let reply = PooledReply::new(pool.get(), 7);
        let debug = format!("{reply:?}");
        assert_eq!(debug, "PooledReply { len: 7 }");
    }
}
