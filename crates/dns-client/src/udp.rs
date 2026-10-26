use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::time::timeout;

use crate::ClientError;

/// UDP transport for upstream DNS queries.
///
/// Every exchange uses a fresh, connected socket. This provides an ephemeral
/// source port per query and lets the kernel drop datagrams from any address
/// other than the server we asked, which is important for spoofing resistance.
#[derive(Clone, Debug, Default)]
pub struct UdpClient {
    bind_addr: Option<IpAddr>,
}

impl UdpClient {
    /// Create a client, optionally binding outgoing sockets to `bind_addr`.
    pub fn new(bind_addr: Option<SocketAddr>) -> std::io::Result<Self> {
        Ok(Self {
            bind_addr: bind_addr.map(|addr| addr.ip()),
        })
    }

    fn local_addr(&self, server: SocketAddr) -> SocketAddr {
        let bind = self.bind_addr.unwrap_or(match server {
            SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        });
        SocketAddr::new(bind, 0)
    }

    /// Send `query` to `server` and wait up to `dur` for a response.
    pub async fn send_recv(
        &self,
        server: SocketAddr,
        query: &[u8],
        dur: Duration,
    ) -> Result<Vec<u8>, ClientError> {
        let socket = UdpSocket::bind(self.local_addr(server)).await?;
        socket.connect(server).await?;
        socket.send(query).await?;

        // EDNS can advertise up to 65535 bytes, so do not cap the read buffer.
        let mut buf = vec![0u8; 65_535];
        match timeout(dur, socket.recv(&mut buf)).await {
            Ok(Ok(len)) => {
                buf.truncate(len);
                Ok(buf)
            }
            Ok(Err(error)) => Err(ClientError::Io(error)),
            Err(_) => Err(ClientError::Timeout),
        }
    }
}
