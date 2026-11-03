//! Single-flight registry: coalesce identical concurrent queries.

use std::sync::Arc;

use dashmap::DashMap;
use dns_proto::Name;
use tokio::sync::{Mutex, watch};

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

#[derive(Clone)]
struct InFlight {
    tx: watch::Sender<Option<Arc<Vec<u8>>>>,
}

#[derive(Clone)]
pub struct QueryRegistry {
    inflight: Arc<DashMap<QueryKey, Arc<Mutex<Option<InFlight>>>>>,
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
        }
    }

    /// Join an in-flight query for `key`, or become its leader.
    ///
    /// The returned [`RegistryEntry::Follower`] channel always observes the
    /// current state, so a follower that arrives just after the leader finishes
    /// still receives the result instead of waiting forever.
    pub async fn wait_or_register(&self, key: QueryKey) -> RegistryEntry {
        let entry = self
            .inflight
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(None)));
        let mut guard = entry.lock().await;

        if let Some(inflight) = guard.as_ref() {
            let rx = inflight.tx.subscribe();
            drop(guard);
            return RegistryEntry::Follower { rx };
        }

        let (tx, _) = watch::channel(None);
        *guard = Some(InFlight { tx: tx.clone() });
        drop(guard);

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn follower_racing_completion_still_sees_the_result() {
        let registry = QueryRegistry::new();
        let RegistryEntry::Leader(leader) = registry.wait_or_register(key()).await else {
            panic!("first caller must lead");
        };

        // Hold the entry's inner lock so the racing caller parks inside
        // `wait_or_register` while holding the DashMap shard guard. The
        // leader's `complete` then publishes and blocks on that shard,
        // pinning the follower's subscription to after the publish.
        let cell = Arc::clone(
            &registry
                .inflight
                .get(&key())
                .expect("leader entry is registered"),
        );
        let inner = cell.lock().await;

        let racing = tokio::spawn({
            let registry = registry.clone();
            async move { registry.wait_or_register(key()).await }
        });
        tokio::time::sleep(Duration::from_millis(5)).await;

        let completing = tokio::spawn(async move {
            leader.complete(Arc::new(vec![7]));
        });
        tokio::time::sleep(Duration::from_millis(5)).await;

        drop(inner);

        match racing.await.expect("task joins") {
            RegistryEntry::Follower { mut rx } => {
                let value = tokio::time::timeout(
                    Duration::from_secs(1),
                    rx.wait_for(|value| value.is_some()),
                )
                .await
                .expect("a completed leader must publish to racing followers")
                .expect("follower channel stays open");
                assert_eq!(value.as_deref(), Some(&vec![7]));
            }
            // The entry was already removed, so this caller leads instead.
            RegistryEntry::Leader(leader) => leader.complete(Arc::new(vec![7])),
        }
        completing.await.expect("task joins");
    }
}
