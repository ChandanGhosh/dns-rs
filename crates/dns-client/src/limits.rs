//! Descriptor-aware bounds for idle connection pools.
//!
//! Pooled sockets stay open between queries, so an unbounded pool can exhaust
//! the process's descriptor limit. Containers commonly run with a 1024-FD soft
//! limit; four pools sized for a machine with a million descriptors will hit
//! `EMFILE` long before they fill. The bounds below are derived from the
//! actual soft limit so the pools fit with room left for listeners, control
//! sockets, and exchanges that are still in flight.

use std::sync::OnceLock;

use tracing::warn;

/// Shards in each upstream pool. Kept here because every transport uses the
/// same sharding scheme.
pub(crate) const SHARD_COUNT: usize = 32;
/// Largest number of distinct upstream servers tracked per shard.
pub(crate) const MAX_SERVERS_PER_SHARD: usize = 32;

/// Descriptors held back for listeners, the control socket, state files, and
/// in-flight exchanges. Ample for `num-threads` UDP sockets plus a few TCP,
/// DoT, and DoH listeners even on a many-core host.
const RESERVED_FDS: u64 = 512;
/// Number of transports that keep idle pools (UDP, TCP, TLS, HTTPS).
const TRANSPORT_COUNT: u64 = 4;
/// Upper bound per transport so a huge descriptor limit does not translate
/// into tens of thousands of idle sockets.
const MAX_CAPACITY: usize = 4096;
/// Soft limit assumed when the real one cannot be read.
const FALLBACK_LIMIT: u64 = 1024;
/// Soft limit recommended for full pool capacity and in-flight headroom.
const RECOMMENDED_LIMIT: u64 = 65_536;

/// Upper bound on idle descriptors for one transport pool.
pub(crate) fn idle_pool_capacity() -> usize {
    static CAPACITY: OnceLock<usize> = OnceLock::new();
    *CAPACITY.get_or_init(|| {
        let queried = soft_no_file_limit();
        let limit = queried.unwrap_or(FALLBACK_LIMIT);
        let capacity = capacity_from_limit(limit);
        if capacity < MAX_CAPACITY {
            warn!(
                soft_limit = limit,
                pool_capacity = capacity,
                recommended_limit = RECOMMENDED_LIMIT,
                assumed = queried.is_none(),
                "low RLIMIT_NOFILE; upstream pools are reduced; raise the soft limit with \
                 systemd LimitNOFILE=65536 or container --ulimit nofile=65536:65536 for better QPS"
            );
        }
        capacity
    })
}

/// Pure form of the capacity calculation, kept separate for testing.
fn capacity_from_limit(soft_limit: u64) -> usize {
    let usable = soft_limit.saturating_sub(RESERVED_FDS) / TRANSPORT_COUNT;
    usize::try_from(usable)
        .unwrap_or(usize::MAX)
        .min(MAX_CAPACITY)
}

#[allow(unsafe_code)]
fn soft_no_file_limit() -> Option<u64> {
    // SAFETY: `getrlimit` writes only to the local `rlimit` struct and does not
    // retain the pointer. `RLIMIT_NOFILE` is a read-only query with no side
    // effects, and the struct is zero-initialised before the call.
    unsafe {
        let mut limit: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
            Some(limit.rlim_cur as u64)
        } else {
            None
        }
    }
}

/// Derive per-shard pool parameters that cannot exceed `capacity` idle sockets
/// in total.
///
/// Both dimensions shrink together: a low descriptor limit may allow only one
/// idle socket per server and fewer tracked servers per shard. The structural
/// bound means no atomic counter is needed on the hot path.
///
/// # Arguments
///
/// * `capacity` - Maximum idle sockets for this transport
/// * `max_idle_per_server` - Per-server ideal from the pool implementation
///
/// # Returns
///
/// `(idle_per_server, servers_per_shard)`
pub(crate) fn pool_parameters(capacity: usize, max_idle_per_server: usize) -> (usize, usize) {
    let idle = (capacity / (SHARD_COUNT * MAX_SERVERS_PER_SHARD)).clamp(1, max_idle_per_server);
    let servers = (capacity / (SHARD_COUNT * idle)).clamp(1, MAX_SERVERS_PER_SHARD);
    (idle, servers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capacity_scales_with_the_soft_limit() {
        assert_eq!(capacity_from_limit(0), 0);
        assert_eq!(capacity_from_limit(RESERVED_FDS), 0);
        assert_eq!(capacity_from_limit(1024), 128);
        assert_eq!(capacity_from_limit(2048), 384);
        assert_eq!(capacity_from_limit(RECOMMENDED_LIMIT), MAX_CAPACITY);
        assert_eq!(capacity_from_limit(u64::MAX), MAX_CAPACITY);
    }

    #[test]
    fn pool_parameters_never_exceed_capacity() {
        for max_idle in [1, 4, 16] {
            for capacity in [1, 32, 128, 384, 4096, MAX_CAPACITY] {
                let (idle, servers) = pool_parameters(capacity, max_idle);
                assert!((1..=max_idle).contains(&idle));
                assert!((1..=MAX_SERVERS_PER_SHARD).contains(&servers));
                assert!(
                    SHARD_COUNT * servers * idle <= capacity.max(SHARD_COUNT),
                    "capacity={capacity} max_idle={max_idle} idle={idle} servers={servers}"
                );
            }
        }
    }

    #[test]
    fn four_transports_fit_inside_the_soft_limit() {
        for soft in [1024, 2048, 4096, 65_536] {
            let per_transport = capacity_from_limit(soft);
            assert!(
                TRANSPORT_COUNT as usize * per_transport <= soft as usize - RESERVED_FDS as usize,
                "soft={soft} per_transport={per_transport}"
            );
        }
    }

    #[test]
    fn full_limit_keeps_the_original_bounds() {
        let (idle, servers) = pool_parameters(MAX_CAPACITY, 16);
        assert_eq!(idle, 4);
        assert_eq!(servers, 32);
        assert_eq!(SHARD_COUNT * servers * idle, 4096);
    }
}
