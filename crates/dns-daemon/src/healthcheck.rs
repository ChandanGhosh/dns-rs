//! Container health probe.
//!
//! The image is based on a distroless runtime, so it has no shell, `dig`, or
//! other utilities to run as a healthcheck. This module implements a minimal
//! probe in the daemon binary itself: it loads the same configuration as the
//! server, picks a plain-DNS listener, and asks for the built-in `localhost.`
//! record. A successful DNS response proves that the process is up and its
//! socket is accepting queries.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use dns_config::Config;
use dns_proto::{
    Message, MessageType, Name, OpCode, Query, RecordType, ResponseCode, decode, encode,
};

/// Options supplied on the command line.
#[derive(Debug, Clone, Copy)]
pub struct Options<'a> {
    /// Address to probe. Defaults to the first configured plain-DNS listener.
    pub address: Option<IpAddr>,
    /// Port to probe. Defaults to the selected listener's port.
    pub port: Option<u16>,
    /// Query name. Defaults to the built-in `localhost.` record.
    pub name: &'a str,
    /// Per-operation timeout.
    pub timeout: Duration,
    /// Use TCP even when the listener supports UDP.
    pub tcp: bool,
}

/// A resolved probe destination.
#[derive(Debug, Clone)]
struct Probe {
    address: SocketAddr,
    name: Name,
    timeout: Duration,
    tcp: bool,
}

impl Probe {
    fn run(&self) -> Result<()> {
        let id = message_id();
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(self.name.clone(), RecordType::A));
        let wire = encode(&query).context("failed to encode healthcheck query")?;

        let response = if self.tcp {
            query_tcp(self.address, &wire, self.timeout)
        } else {
            query_udp(self.address, &wire, self.timeout)
        }
        .with_context(|| {
            format!(
                "no DNS response from {} ({})",
                self.address,
                if self.tcp { "tcp" } else { "udp" }
            )
        })?;

        let message = decode(&response).context("failed to decode healthcheck response")?;
        if message.metadata.id != id || message.metadata.message_type != MessageType::Response {
            bail!("healthcheck response did not match the query");
        }
        if message.metadata.response_code != ResponseCode::NoError {
            bail!(
                "healthcheck query returned {}",
                message.metadata.response_code
            );
        }
        Ok(())
    }
}

/// Run one health probe against a running daemon.
pub fn run(config_path: &Path, options: &Options<'_>) -> Result<()> {
    let loaded = dns_config::load(config_path)
        .with_context(|| format!("failed to load configuration {}", config_path.display()))?;
    let probe = probe_from_config(&loaded.config, options)?;
    probe.run()?;
    println!(
        "ok: {} {} {}",
        probe.address,
        if probe.tcp { "tcp" } else { "udp" },
        probe.name
    );
    Ok(())
}

fn probe_from_config(config: &Config, options: &Options<'_>) -> Result<Probe> {
    let (listener, tcp) = match options.address {
        Some(address) => {
            let port = options.port.unwrap_or(config.server.port);
            (loopback_for(address, port), !config.server.do_udp)
        }
        None => {
            select_listener(config).context("no plain-DNS listener found in the configuration")?
        }
    };

    let name = if options.name.ends_with('.') {
        options.name.to_owned()
    } else {
        format!("{}.", options.name)
    };

    Ok(Probe {
        address: listener,
        name: Name::from_ascii(&name).with_context(|| format!("invalid probe name {name:?}"))?,
        timeout: options.timeout,
        tcp: options.tcp || tcp,
    })
}

/// Pick the first configured plain-DNS listener that the server would start.
///
/// Interfaces bound to the TLS or HTTPS port are skipped, as are address
/// families that are disabled. Wildcard addresses are reached through loopback.
fn select_listener(config: &Config) -> Option<(SocketAddr, bool)> {
    let tcp = !config.server.do_udp;
    for iface in &config.server.interfaces {
        let addr = iface.socket_addr(config.server.port);
        if addr.port() == config.server.tls_port || addr.port() == config.server.https_port {
            continue;
        }
        if addr.is_ipv4() && !config.server.do_ip4 {
            continue;
        }
        if addr.is_ipv6() && !config.server.do_ip6 {
            continue;
        }
        if !config.server.do_udp && !config.server.do_tcp {
            continue;
        }
        return Some((loopback_for(addr.ip(), addr.port()), tcp));
    }
    None
}

/// Replace a wildcard bind address with the matching loopback address.
fn loopback_for(address: IpAddr, port: u16) -> SocketAddr {
    match address {
        IpAddr::V4(address) if address.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
        }
        IpAddr::V6(address) if address.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port)
        }
        address => SocketAddr::new(address, port),
    }
}

fn query_udp(address: SocketAddr, query: &[u8], timeout: Duration) -> Result<Vec<u8>> {
    let bind = match address {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind).context("failed to create probe socket")?;
    socket
        .set_read_timeout(Some(timeout))
        .context("failed to set probe timeout")?;
    socket
        .connect(address)
        .context("failed to connect probe socket")?;
    socket.send(query).context("failed to send probe query")?;

    let mut response = vec![0; 65_535];
    let len = socket
        .recv(&mut response)
        .context("probe timed out waiting for a response")?;
    response.truncate(len);
    Ok(response)
}

fn query_tcp(address: SocketAddr, query: &[u8], timeout: Duration) -> Result<Vec<u8>> {
    let mut stream =
        TcpStream::connect_timeout(&address, timeout).context("failed to connect probe socket")?;
    stream
        .set_read_timeout(Some(timeout))
        .context("failed to set probe read timeout")?;
    stream
        .set_write_timeout(Some(timeout))
        .context("failed to set probe write timeout")?;

    let len = u16::try_from(query.len()).context("probe query is too large")?;
    stream
        .write_all(&len.to_be_bytes())
        .context("failed to write probe length")?;
    stream
        .write_all(query)
        .context("failed to write probe query")?;

    let mut prefix = [0_u8; 2];
    stream
        .read_exact(&mut prefix)
        .context("probe timed out waiting for a response")?;
    let len = usize::from(u16::from_be_bytes(prefix));
    let mut response = vec![0; len];
    stream
        .read_exact(&mut response)
        .context("probe response was truncated")?;
    Ok(response)
}

fn message_id() -> u16 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.subsec_nanos())
        .unwrap_or(0);
    (nanos as u16) ^ (std::process::id() as u16)
}

#[cfg(test)]
mod tests {
    use std::thread;

    use dns_config::ListenAddress;
    use dns_proto::{MessageType, Name, OpCode, RData, Record, decode, encode};

    use super::*;

    fn listener(address: &str, port: u16) -> ListenAddress {
        ListenAddress::new(address.parse().expect("valid IP"), Some(port))
    }

    #[test]
    fn wildcard_listeners_are_probed_through_loopback() {
        let mut config = Config::default();
        config.server.port = 53;
        config.server.interfaces = vec![listener("0.0.0.0", 53)];

        let (address, tcp) = select_listener(&config).expect("listener is selected");
        assert_eq!(address, "127.0.0.1:53".parse().expect("valid socket"));
        assert!(!tcp);
    }

    #[test]
    fn encrypted_listeners_are_skipped() {
        let mut config = Config::default();
        config.server.tls_port = 853;
        config.server.interfaces = vec![
            listener("0.0.0.0", 853),
            listener("::", 443),
            listener("0.0.0.0", 53),
        ];

        let (address, _) = select_listener(&config).expect("listener is selected");
        assert_eq!(address, "127.0.0.1:53".parse().expect("valid socket"));
    }

    #[test]
    fn tcp_is_selected_when_udp_is_disabled() {
        let mut config = Config::default();
        config.server.do_udp = false;
        config.server.interfaces = vec![listener("127.0.0.1", 5353)];

        let (_, tcp) = select_listener(&config).expect("listener is selected");
        assert!(tcp);
    }

    #[test]
    fn probes_a_udp_listener() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("bind probe server");
        let address = server.local_addr().expect("server address");
        let responder = thread::spawn(move || {
            let mut buffer = [0_u8; 512];
            let (len, peer) = server.recv_from(&mut buffer).expect("receive query");
            let query = decode(&buffer[..len]).expect("decode query");
            let mut response =
                Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
            response.add_query(query.queries[0].clone());
            response.add_answer(Record::from_rdata(
                Name::from_ascii("localhost.").expect("valid name"),
                60,
                RData::A(Ipv4Addr::LOCALHOST.into()),
            ));
            server
                .send_to(&encode(&response).expect("encode response"), peer)
                .expect("send response");
        });

        let probe = Probe {
            address,
            name: Name::from_ascii("localhost.").expect("valid name"),
            timeout: Duration::from_secs(2),
            tcp: false,
        };
        probe.run().expect("probe succeeds");
        responder.join().expect("responder exits");
    }
}
