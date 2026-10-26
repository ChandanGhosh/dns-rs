//! Upstream DNS transports used by the iterative resolver.

mod https;
mod tcp;
mod tls;
mod udp;

pub use https::HttpsClient;
pub use tcp::TcpClient;
pub use tls::TlsClient;
pub use udp::UdpClient;

use std::fmt;
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::timeout;

/// An upstream DNS transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    /// Classic DNS over UDP.
    Udp,
    /// DNS over TCP.
    Tcp,
    /// DNS over TLS (RFC 7858).
    Tls,
    /// DNS over HTTPS (RFC 8484).
    Https,
    /// DNS over QUIC (RFC 9250).
    Quic,
}

impl fmt::Display for Transport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Udp => "udp",
            Self::Tcp => "tcp",
            Self::Tls => "tls",
            Self::Https => "https",
            Self::Quic => "quic",
        };
        formatter.write_str(name)
    }
}

/// Upstream exchange result
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("timeout")]
    Timeout,
    #[error("truncated")]
    Truncated,
    #[error("TLS error: {0}")]
    Tls(String),
    #[error("HTTP error: {0}")]
    Http(String),
}

/// Write one length-prefixed DNS message and read the length-prefixed reply.
///
/// Shared by the stream transports (TCP and TLS) so framing and timeout
/// behavior stay identical.
pub(crate) async fn exchange<S>(
    stream: &mut S,
    query: &[u8],
    dur: Duration,
) -> Result<Vec<u8>, ClientError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut out = Vec::with_capacity(query.len() + 2);
    out.push((query.len() >> 8) as u8);
    out.push(query.len() as u8);
    out.extend_from_slice(query);
    timeout(dur, stream.write_all(&out))
        .await
        .map_err(|_| ClientError::Timeout)??;

    let mut lenbuf = [0u8; 2];
    timeout(dur, stream.read_exact(&mut lenbuf))
        .await
        .map_err(|_| ClientError::Timeout)??;
    let len = usize::from(u16::from_be_bytes(lenbuf));
    if len == 0 {
        return Err(ClientError::Truncated);
    }
    let mut response = vec![0u8; len];
    timeout(dur, stream.read_exact(&mut response))
        .await
        .map_err(|_| ClientError::Timeout)??;
    Ok(response)
}
