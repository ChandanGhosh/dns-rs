//! Message-cache, coalescing, prefetch, serve-stale, and cancellation tests.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use dns_config::{Config, ForwardTarget, ForwardZoneConfig};
use dns_proto::{
    Message, MessageType, OpCode, RData, Record, RecordType, ResponseCode, decode, encode,
};
use dns_server::{QueryPipeline, Transport};
use dns_testutil::query_bytes;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

struct MockForwarder {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
}

impl MockForwarder {
    async fn start(delay: Duration, ttl: u32) -> Self {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind"));
        let addr = socket.local_addr().expect("local address");
        let queries = Arc::new(AtomicUsize::new(0));

        let counter = Arc::clone(&queries);
        let listener = Arc::clone(&socket);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                let Ok((len, peer)) = listener.recv_from(&mut buf).await else {
                    break;
                };
                let Ok(query) = decode(&buf[..len]) else {
                    continue;
                };
                counter.fetch_add(1, Ordering::SeqCst);

                let Some(wire) = encode(&reply(&query, ttl)).ok() else {
                    continue;
                };
                let socket = Arc::clone(&listener);
                tokio::spawn(async move {
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    let _ = socket.send_to(&wire, peer).await;
                });
            }
        });

        Self { addr, queries }
    }

    fn count(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

fn reply(query: &Message, ttl: u32) -> Message {
    let mut message = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    message.metadata.recursion_available = true;
    message.metadata.response_code = ResponseCode::NoError;
    if let Some(question) = query.queries.first() {
        message.add_query(question.clone());
        message.add_answer(Record::from_rdata(
            question.name.clone(),
            ttl,
            RData::A(Ipv4Addr::new(192, 0, 2, 1).into()),
        ));
    }
    message
}

fn config(forwarder: SocketAddr) -> Config {
    let mut config = Config::default();
    config.server.do_ip6 = false;
    config.server.use_caps_for_id = false;
    config.server.qname_minimisation = false;
    config.server.dnssec_validation = false;
    // The coalescing test sends 1,000 queries from one client address.
    config.server.max_concurrent_queries_per_client = 2_048;
    config.forward_zones = vec![ForwardZoneConfig {
        name: ".".to_owned(),
        forward_addrs: vec![ForwardTarget::new(forwarder, None)],
        forward_hosts: Vec::new(),
        forward_first: false,
        tls_upstream: false,
    }];
    config
}

fn client() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53000)
}

fn assert_answer(wire: &[u8]) {
    let message = decode(wire).expect("decode response");
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert!(
        message
            .answers
            .iter()
            .any(|record| matches!(record.data, RData::A(address) if address.0 == Ipv4Addr::new(192, 0, 2, 1))),
        "expected the forwarder answer"
    );
}

#[tokio::test]
async fn one_thousand_identical_queries_use_one_upstream_query() {
    let forwarder = MockForwarder::start(Duration::from_millis(200), 300).await;
    let pipeline = Arc::new(QueryPipeline::new(Arc::new(config(forwarder.addr))));
    let bytes = Arc::new(query_bytes("example.com.", RecordType::A));

    let mut tasks = Vec::with_capacity(1_000);
    for _ in 0..1_000 {
        let pipeline = Arc::clone(&pipeline);
        let bytes = Arc::clone(&bytes);
        tasks.push(tokio::spawn(async move {
            pipeline.handle(&bytes, client(), Transport::Udp).await
        }));
    }

    for task in tasks {
        let response = task.await.expect("task").expect("response");
        assert_answer(&response);
    }

    assert_eq!(
        forwarder.count(),
        1,
        "all concurrent identical queries must coalesce into one upstream query"
    );
}

#[tokio::test]
async fn second_query_is_a_cache_hit_and_stats_are_exported() {
    let forwarder = MockForwarder::start(Duration::ZERO, 300).await;
    let pipeline = QueryPipeline::new(Arc::new(config(forwarder.addr)));
    let bytes = query_bytes("example.com.", RecordType::A);

    let first = pipeline
        .handle(&bytes, client(), Transport::Udp)
        .await
        .expect("first response");
    assert_answer(&first);

    let second = pipeline
        .handle(&bytes, client(), Transport::Udp)
        .await
        .expect("second response");
    assert_answer(&second);
    assert_eq!(forwarder.count(), 1, "the second query must be a cache hit");

    let stats = pipeline.stats();
    assert_eq!(stats.cache.hits, 1);
    assert!(stats.cache.misses >= 1);
    let metrics = stats.render_prometheus();
    assert!(metrics.contains("dns_rs_cache_hits_total 1"));
    assert!(metrics.contains("dns_rs_cache_entries"));
}

#[tokio::test]
async fn prefetch_refreshes_an_entry_near_expiry() {
    let forwarder = MockForwarder::start(Duration::ZERO, 1).await;
    let mut config = config(forwarder.addr);
    config.server.prefetch = true;
    let pipeline = QueryPipeline::new(Arc::new(config));
    let bytes = query_bytes("example.com.", RecordType::A);

    pipeline
        .handle(&bytes, client(), Transport::Udp)
        .await
        .expect("first response");
    pipeline
        .handle(&bytes, client(), Transport::Udp)
        .await
        .expect("second response");

    // The second hit is inside the prefetch threshold and starts a background
    // refresh. Give it a moment to reach the forwarder.
    for _ in 0..50 {
        if forwarder.count() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(forwarder.count(), 2, "prefetch must refresh the entry");
    assert!(pipeline.stats().prefetches >= 1);
}

#[tokio::test]
async fn serve_expired_answers_stale_and_refreshes() {
    let forwarder = MockForwarder::start(Duration::ZERO, 1).await;
    let mut config = config(forwarder.addr);
    config.server.serve_expired = true;
    config.server.serve_expired_ttl = 30;
    config.server.serve_expired_reply_ttl = 5;
    let pipeline = QueryPipeline::new(Arc::new(config));
    let bytes = query_bytes("example.com.", RecordType::A);

    pipeline
        .handle(&bytes, client(), Transport::Udp)
        .await
        .expect("first response");
    tokio::time::sleep(Duration::from_millis(1_200)).await;

    let stale = pipeline
        .handle(&bytes, client(), Transport::Udp)
        .await
        .expect("stale response");
    let message = decode(&stale).expect("decode stale response");
    assert_eq!(message.metadata.response_code, ResponseCode::NoError);
    assert_eq!(message.answers[0].ttl, 5, "stale replies carry a short TTL");

    for _ in 0..50 {
        if forwarder.count() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        forwarder.count(),
        2,
        "serve-expired must refresh in the background"
    );
    assert!(pipeline.stats().cache.stale_hits >= 1);
}

#[tokio::test]
async fn cancelling_a_leader_releases_followers() {
    let forwarder = MockForwarder::start(Duration::from_secs(5), 300).await;
    let pipeline = Arc::new(QueryPipeline::new(Arc::new(config(forwarder.addr))));
    let bytes = Arc::new(query_bytes("example.com.", RecordType::A));

    let cancel = CancellationToken::new();
    let leader = {
        let pipeline = Arc::clone(&pipeline);
        let bytes = Arc::clone(&bytes);
        let cancel = cancel.clone();
        tokio::spawn(async move {
            pipeline
                .handle_with_cancel(&bytes, client(), Transport::Udp, cancel)
                .await
        })
    };

    // Wait until the leader has actually sent the upstream query.
    for _ in 0..100 {
        if forwarder.count() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(forwarder.count(), 1);

    let follower = {
        let pipeline = Arc::clone(&pipeline);
        let bytes = Arc::clone(&bytes);
        tokio::spawn(async move { pipeline.handle(&bytes, client(), Transport::Udp).await })
    };
    // Let the follower join the in-flight query.
    tokio::time::sleep(Duration::from_millis(50)).await;

    cancel.cancel();

    let leader_response = tokio::time::timeout(Duration::from_secs(1), leader)
        .await
        .expect("cancelled leader returns promptly")
        .expect("leader task");
    assert!(leader_response.is_none());

    let follower_response = tokio::time::timeout(Duration::from_secs(2), follower)
        .await
        .expect("follower is released promptly")
        .expect("follower task");
    let message = decode(&follower_response.expect("SERVFAIL response")).expect("decode");
    assert_eq!(message.metadata.response_code, ResponseCode::ServFail);
}
