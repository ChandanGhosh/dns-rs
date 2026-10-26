//! The query pipeline must drop malformed packets without panicking.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use dns_config::Config;
use dns_server::{QueryPipeline, Transport};

#[tokio::test]
async fn pipeline_drops_malformed_packets() {
    let pipeline = QueryPipeline::new(Arc::new(Config::default()));
    let client = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53000);

    let cases: &[&[u8]] = &[
        &[],
        &[0x00],
        // Truncated header.
        &[0x12, 0x34, 0x01, 0x00, 0x00],
        // One question claimed, but the packet ends after the header.
        &[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ],
        // Compression pointer that points at itself.
        &[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc0, 0x0c,
            0x00, 0x01, 0x00, 0x01,
        ],
    ];

    for bytes in cases {
        assert!(
            pipeline
                .handle(bytes, client, Transport::Udp)
                .await
                .is_none(),
            "malformed packet must be dropped"
        );
    }
}
