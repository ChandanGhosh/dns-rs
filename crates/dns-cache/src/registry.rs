//! Single-flight registry: coalesce identical concurrent queries.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use dashmap::DashMap;
use dns_proto::Name;
use tokio::sync::watch;

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct QueryKey {
    /// Query name; `Name` compares case-insensitively, so keys match without
    /// formatting the name into a lowercased string.
    pub name: Name,
    pub qtype: u16,
    pub qclass: u16,
    /// EDNS DO bit, which changes whether signatures are included.
    pub do_bit: bool,
    /// Client CD bit, which changes validation failure handling.
    pub checking_disabled: bool,
}

/// Point-in-time snapshot of single-flight registry counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CoalesceStats {
    /// Queries that started their own upstream resolution.
    pub leaders: u64,
    /// Queries that joined an in-flight resolution instead of starting one.
    pub followers: u64,
    /// Leaders dropped without publishing, e.g. because the client went away.
    pub abandoned: u64,
}

/// Shared counters behind [`CoalesceStats`]; relaxed ordering is enough
/// because the values are only ever read for reporting.
#[derive(Default)]
struct RegistryCounters {
    leaders: AtomicU64,
    followers: AtomicU64,
    abandoned: AtomicU64,
}

impl RegistryCounters {
    fn snapshot(&self) -> CoalesceStats {
        CoalesceStats {
            leaders: self.leaders.load(Ordering::Relaxed),
            followers: self.followers.load(Ordering::Relaxed),
            abandoned: self.abandoned.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone)]
struct InFlight {
    tx: watch::Sender<Option<Arc<Vec<u8>>>>,
}

#[derive(Clone)]
pub struct QueryRegistry {
    inflight: Arc<DashMap<QueryKey, Arc<Mutex<Option<InFlight>>>>>,
    counters: Arc<RegistryCounters>,
}

impl std::fmt::Debug for QueryRegistry {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QueryRegistry")
            .field("inflight", &self.inflight.len())
            .finish()
    }
}

impl QueryRegistry {
    pub fn new() -> Self {
        Self {
            inflight: Arc::new(DashMap::new()),
            counters: Arc::new(RegistryCounters::default()),
        }
    }

    /// Return the current leader, follower, and abandoned-leader counts.
    pub fn stats(&self) -> CoalesceStats {
        self.counters.snapshot()
    }

    /// Join an in-flight query for `key`, or become its leader.
    ///
    /// The returned [`RegistryEntry::Follower`] channel always observes the
    /// current state, so a follower that arrives just after the leader finishes
    /// still receives the result instead of waiting forever.
    ///
    /// The per-key mutex is synchronous: the critical section only inspects and
    /// updates the entry, so it never awaits and cannot stall the shard guard
    /// that `DashMap::entry` holds while the lookup runs.
    pub async fn wait_or_register(&self, key: QueryKey) -> RegistryEntry {
        let entry = self
            .inflight
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(None)));
        let mut guard = entry.lock().unwrap_or_else(|error| error.into_inner());

        if let Some(inflight) = guard.as_ref() {
            self.counters.followers.fetch_add(1, Ordering::Relaxed);
            let rx = inflight.tx.subscribe();
            drop(guard);
            return RegistryEntry::Follower { rx };
        }

        let (tx, _) = watch::channel(None);
        *guard = Some(InFlight { tx: tx.clone() });
        drop(guard);
        self.counters.leaders.fetch_add(1, Ordering::Relaxed);

        RegistryEntry::Leader(LeaderGuard {
            key,
            registry: self.clone(),
            tx,
            completed: false,
        })
    }

    fn remove(&self, key: &QueryKey) {
        self.inflight.remove(key);
    }
}

impl Default for QueryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum RegistryEntry {
    Leader(LeaderGuard),
    Follower {
        rx: watch::Receiver<Option<Arc<Vec<u8>>>>,
    },
}

/// Owns leadership for one query. Dropping without [`LeaderGuard::complete`]
/// releases waiters with an error result instead of leaving them stuck.
#[derive(Debug)]
pub struct LeaderGuard {
    key: QueryKey,
    registry: QueryRegistry,
    tx: watch::Sender<Option<Arc<Vec<u8>>>>,
    completed: bool,
}

impl LeaderGuard {
    pub fn complete(mut self, response: Arc<Vec<u8>>) {
        // `send` refuses to store the value while no follower is subscribed,
        // but a follower may subscribe between this publish and the entry's
        // removal below. `send_replace` always stores, so such a follower
        // reads the result instead of a closed channel.
        self.tx.send_replace(Some(response));
        self.completed = true;
        self.registry.remove(&self.key);
    }
}

impl Drop for LeaderGuard {
    fn drop(&mut self) {
        if !self.completed {
            // Closing the sender releases followers with an error.
            self.registry
                .counters
                .abandoned
                .fetch_add(1, Ordering::Relaxed);
            self.registry.remove(&self.key);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use dns_proto::Name;

    use super::{QueryKey, QueryRegistry, RegistryEntry};

    fn key() -> QueryKey {
        QueryKey {
            name: Name::from_ascii("example.com.").expect("name"),
            qtype: 1,
            qclass: 1,
            do_bit: false,
            checking_disabled: false,
        }
    }

    #[tokio::test]
    async fn stats_count_leaders_followers_and_abandoned_leaders() {
        let registry = QueryRegistry::new();
        assert_eq!(registry.stats().leaders, 0);

        let RegistryEntry::Leader(leader) = registry.wait_or_register(key()).await else {
            panic!("first caller must lead");
        };
        let RegistryEntry::Follower { rx: _ } = registry.wait_or_register(key()).await else {
            panic!("second caller must follow");
        };
        let stats = registry.stats();
        assert_eq!(stats.leaders, 1);
        assert_eq!(stats.followers, 1);
        assert_eq!(stats.abandoned, 0);

        // Dropping the leader without completing it counts as abandoned.
        drop(leader);
        let stats = registry.stats();
        assert_eq!(stats.abandoned, 1);
        assert_eq!(stats.leaders, 1, "counters are cumulative");

        // A completed leader is not abandoned.
        let RegistryEntry::Leader(leader) = registry.wait_or_register(key()).await else {
            panic!("entry was removed, so the caller leads");
        };
        leader.complete(Arc::new(vec![1]));
        assert_eq!(registry.stats().abandoned, 1);
    }

    #[tokio::test]
    async fn followers_receive_leader_result() {
        let registry = QueryRegistry::new();
        let RegistryEntry::Leader(leader) = registry.wait_or_register(key()).await else {
            panic!("first caller must lead");
        };
        let RegistryEntry::Follower { mut rx } = registry.wait_or_register(key()).await else {
            panic!("second caller must follow");
        };

        leader.complete(Arc::new(vec![1, 2, 3]));
        let value = rx
            .wait_for(|value| value.is_some())
            .await
            .expect("result arrives");
        assert_eq!(value.as_deref(), Some(&vec![1, 2, 3]));
    }

    #[tokio::test]
    async fn follower_arriving_after_completion_sees_result() {
        let registry = QueryRegistry::new();
        let RegistryEntry::Leader(leader) = registry.wait_or_register(key()).await else {
            panic!("first caller must lead");
        };
        // Follower registers while the leader is still in flight, which is the
        // only observable state; check the value is delivered even if it is
        // published before the follower starts waiting.
        let RegistryEntry::Follower { mut rx } = registry.wait_or_register(key()).await else {
            panic!("second caller must follow");
        };
        leader.complete(Arc::new(vec![9]));
        let value = tokio::time::timeout(Duration::from_secs(1), rx.wait_for(|v| v.is_some()))
            .await
            .expect("does not hang")
            .expect("result arrives");
        assert_eq!(value.as_deref(), Some(&vec![9]));
    }

    #[tokio::test]
    async fn leader_drop_releases_followers() {
        let registry = QueryRegistry::new();
        let RegistryEntry::Leader(leader) = registry.wait_or_register(key()).await else {
            panic!("first caller must lead");
        };
        let RegistryEntry::Follower { mut rx } = registry.wait_or_register(key()).await else {
            panic!("second caller must follow");
        };
        drop(leader);
        let result = tokio::time::timeout(Duration::from_secs(1), rx.wait_for(|v| v.is_some()))
            .await
            .expect("does not hang");
        assert!(result.is_err(), "closed channel signals failure");
    }

    #[tokio::test]
    async fn new_leader_can_register_after_completion() {
        let registry = QueryRegistry::new();
        let RegistryEntry::Leader(leader) = registry.wait_or_register(key()).await else {
            panic!("first caller must lead");
        };
        leader.complete(Arc::new(vec![1]));
        let entry = registry.wait_or_register(key()).await;
        assert!(matches!(entry, RegistryEntry::Leader(_)));
    }

    #[tokio::test]
    async fn subscription_after_publish_still_sees_the_result() {
        let registry = QueryRegistry::new();
        let RegistryEntry::Leader(leader) = registry.wait_or_register(key()).await else {
            panic!("first caller must lead");
        };

        // Clone the sender before completion, mirroring a follower that looked
        // up the entry just before the leader removed it.
        let tx = {
            let entry = registry
                .inflight
                .get(&key())
                .expect("leader entry is registered");
            let guard = entry.lock().unwrap_or_else(|error| error.into_inner());
            guard
                .as_ref()
                .expect("leader registered an in-flight entry")
                .tx
                .clone()
        };

        leader.complete(Arc::new(vec![7]));

        // `send_replace` stores the value even with no subscribers, so a
        // subscription created after the publish observes it instead of a
        // closed channel.
        let mut rx = tx.subscribe();
        let value =
            tokio::time::timeout(Duration::from_secs(1), rx.wait_for(|value| value.is_some()))
                .await
                .expect("does not hang")
                .expect("completed leader stays observable");
        assert_eq!(value.as_deref(), Some(&vec![7]));
    }
}
