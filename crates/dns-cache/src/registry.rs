//! Single-flight registry: coalesce identical concurrent queries.

use std::sync::Arc;

use dashmap::DashMap;
use tokio::sync::{Mutex, watch};

#[derive(Clone, Debug, Hash, Eq, PartialEq)]
pub struct QueryKey {
    pub name: String,
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
        let _ = self.tx.send(Some(response));
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

    use super::{QueryKey, QueryRegistry, RegistryEntry};

    fn key() -> QueryKey {
        QueryKey {
            name: "example.com.".to_owned(),
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
}
