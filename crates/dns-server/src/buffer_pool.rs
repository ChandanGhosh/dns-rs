//! Reusable DNS message buffers.
//!
//! Allocating a fresh `Vec<u8>` for every query takes the allocator lock on the
//! hot path. [`BufferPool`] hands out [`PooledBuffer`]s that return their
//! allocation to the pool when dropped, so steady-state traffic reuses the same
//! memory. The RAII wrapper also covers early returns and panics, which manual
//! put-back calls tend to miss.

use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};

/// Largest possible DNS message, and therefore the receive buffer size.
const BUFFER_SIZE: usize = 65_535;
/// Buffers kept for reuse per pool.
const MAX_CAPACITY: usize = 256;

/// A pool of reusable message buffers.
///
/// Cloning shares the same pool; every listener owns one pool, and the clones
/// handed to connection tasks all return buffers to it.
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
}
