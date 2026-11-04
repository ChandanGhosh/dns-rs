//! Process-wide allocation counters behind the `alloc-stats` feature.
//!
//! `CountingMiMalloc` keeps mimalloc as the real allocator and adds one
//! relaxed atomic increment per allocation request, so instrumented builds
//! allocate exactly like production ones. A reporter thread prints
//! `stats allocs=N` on stdout every 250 ms, which `scripts/bench-loopback.sh`
//! snapshots around its load window the same way it reads the mock
//! authority's `stats upstream_queries=N`.

use std::alloc::{GlobalAlloc, Layout};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

/// Allocation requests since process start. `dealloc` is deliberately not
/// counted: the benchmark metric is requests issued per query, and a second
/// atomic on the deallocation path would buy nothing.
static ALLOCS: AtomicU64 = AtomicU64::new(0);

/// Counting wrapper around mimalloc, installed as the global allocator when
/// the `alloc-stats` feature is enabled.
#[derive(Debug)]
pub(crate) struct CountingMiMalloc;

/// Total allocation requests since process start.
fn allocs() -> u64 {
    ALLOCS.load(Ordering::Relaxed)
}

/// Render the reporter line for `count` requests. The bench runner parses
/// this exact shape (`sed -n 's/^stats allocs=//p'`), so the format is a
/// contract with `scripts/bench-loopback.sh`.
fn report_line(count: u64) -> String {
    format!("stats allocs={count}")
}

// The workspace bans `unsafe` by default, but a `GlobalAlloc` wrapper is
// necessarily unsafe: every method hands the caller's raw pointer and layout
// straight to the inner allocator, preserving exactly the contract the trait
// prescribes, with no additional invariants of its own.
#[allow(unsafe_code)]
unsafe impl GlobalAlloc for CountingMiMalloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { mimalloc::MiMalloc.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { mimalloc::MiMalloc.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { mimalloc::MiMalloc.dealloc(ptr, layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        unsafe { mimalloc::MiMalloc.realloc(ptr, layout, new_size) }
    }
}

/// Print `stats allocs=N` on stdout every 250 ms for the lifetime of the
/// process so the runner can bracket a measurement window. Dropping the join
/// handle detaches the thread; it exits with the process.
pub(crate) fn spawn_reporter() {
    let _reporter = thread::spawn(|| {
        loop {
            thread::sleep(Duration::from_millis(250));
            println!("{}", report_line(allocs()));
        }
    });
}

#[cfg(test)]
mod tests {
    use super::{allocs, report_line};

    /// The wrapper is the process-wide allocator under this feature, so a
    /// batch of boxed values must move the counter by at least the batch
    /// size (other threads may contribute more; the counter never
    /// decreases).
    #[test]
    fn counts_boxed_allocations() {
        const BATCH: u64 = 64;
        let before = allocs();
        let held: Vec<Box<u64>> = (0..BATCH).map(Box::new).collect();
        let delta = allocs() - before;
        assert!(
            delta >= BATCH,
            "expected at least {BATCH} allocs, got {delta}"
        );
        drop(held);
    }

    /// The runner parses this shape; keep it stable.
    #[test]
    fn report_line_shape() {
        assert_eq!(report_line(42), "stats allocs=42");
    }
}
