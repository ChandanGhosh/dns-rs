//! Loopback fake authoritative servers driven by replay ranges.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;

use dns_iter::IteratorConfig;
use dns_proto::{
    DNSClass, Edns, Message, MessageType, Name, OpCode, Query, RData, Record, RecordType, decode,
    encode,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;

use crate::error::ReplayError;
use crate::model::{Entry, Range, RecordLine, Reply, Scenario};

/// One upstream query observed by the fake network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryLog {
    /// Replay address of the server that received the query.
    pub address: IpAddr,
    /// Queried owner name.
    pub name: String,
    /// Queried record type.
    pub rtype: String,
    /// Queried class.
    pub class: String,
}

/// Shared state used by every fake server in a scenario.
#[derive(Debug, Default)]
pub struct FakeNetworkState {
    current_time: Mutex<u64>,
    queries: Mutex<Vec<QueryLog>>,
}

impl FakeNetworkState {
    /// Return the simulated time used to select active ranges.
    pub async fn time(&self) -> u64 {
        *self.current_time.lock().await
    }

    /// Set the simulated time used to select active ranges.
    pub async fn set_time(&self, time: u64) {
        *self.current_time.lock().await = time;
    }

    /// Return every upstream query observed so far.
    pub async fn queries(&self) -> Vec<QueryLog> {
        self.queries.lock().await.clone()
    }

    async fn record(&self, log: QueryLog) {
        self.queries.lock().await.push(log);
    }
}

/// Loopback address mapping and shared UDP/TCP port for one scenario.
#[derive(Debug, Clone)]
pub struct AddressMap {
    aliases: HashMap<IpAddr, IpAddr>,
    reverse: HashMap<IpAddr, IpAddr>,
    port: u16,
    root: IpAddr,
}

impl AddressMap {
    /// Return the replay address used as the pinned root server.
    pub fn root(&self) -> IpAddr {
        self.root
    }

    /// Return the loopback address standing in for a replay address.
    pub fn local(&self, address: IpAddr) -> Option<IpAddr> {
        self.aliases.get(&address).copied()
    }

    /// Return the shared fake-server port.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Return aliases from loopback addresses back to replay addresses.
    pub fn reverse(&self) -> &HashMap<IpAddr, IpAddr> {
        &self.reverse
    }

    /// Return the socket address the resolver should use as its root server.
    pub fn root_socket(&self) -> SocketAddr {
        SocketAddr::new(
            self.local(self.root)
                .expect("pinned root address must be present in the alias map"),
            self.port,
        )
    }
}

/// Running fake servers for one scenario.
pub struct FakeNetwork {
    map: AddressMap,
    state: Arc<FakeNetworkState>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl FakeNetwork {
    /// Bind loopback sockets and start serving the scenario's ranges.
    pub async fn start(scenario: &Scenario) -> Result<Self, ReplayError> {
        let originals = unique_addresses(scenario)?;
        if originals.len() > 253 {
            return Err(ReplayError::Scenario {
                scenario: scenario.name.clone(),
                message: "too many server addresses for 127.0.0.0/8 aliases".to_owned(),
            });
        }
        let locals = (1..=originals.len())
            .map(|index| IpAddr::V4(Ipv4Addr::new(127, 0, 0, index as u8)))
            .collect::<Vec<_>>();
        let mut udp_sockets = Vec::with_capacity(originals.len());
        let first = UdpSocket::bind(SocketAddr::new(locals[0], 0)).await?;
        let port = first.local_addr()?.port();
        udp_sockets.push(first);
        for local in locals.iter().skip(1) {
            udp_sockets.push(UdpSocket::bind(SocketAddr::new(*local, port)).await?);
        }
        let mut tcp_listeners = Vec::with_capacity(originals.len());
        for local in &locals {
            tcp_listeners.push(TcpListener::bind(SocketAddr::new(*local, port)).await?);
        }

        let aliases = originals
            .iter()
            .zip(locals.iter())
            .map(|(original, local)| (*original, *local))
            .collect::<HashMap<_, _>>();
        let reverse = aliases.iter().map(|(a, b)| (*b, *a)).collect();
        let map = AddressMap {
            aliases,
            reverse,
            port,
            root: root_address(scenario),
        };
        let state = Arc::new(FakeNetworkState::default());
        let (shutdown, receiver) = watch::channel(false);
        let mut tasks = Vec::with_capacity(originals.len() * 2);
        for (original, socket) in originals.iter().zip(udp_sockets) {
            let ranges = scenario
                .ranges
                .iter()
                .filter(|range| range.address == Some(*original))
                .cloned()
                .collect::<Vec<_>>();
            tasks.push(tokio::spawn(serve_udp(
                *original,
                socket,
                ranges,
                map.clone(),
                Arc::clone(&state),
                receiver.clone(),
            )));
        }
        for (original, listener) in originals.iter().zip(tcp_listeners) {
            let ranges = scenario
                .ranges
                .iter()
                .filter(|range| range.address == Some(*original))
                .cloned()
                .collect::<Vec<_>>();
            tasks.push(tokio::spawn(serve_tcp(
                *original,
                listener,
                ranges,
                map.clone(),
                Arc::clone(&state),
                receiver.clone(),
            )));
        }
        Ok(Self {
            map,
            state,
            shutdown,
            tasks,
        })
    }

    /// Return the address map used by this fake network.
    pub fn map(&self) -> &AddressMap {
        &self.map
    }

    /// Return the shared state used by this fake network.
    pub fn state(&self) -> &Arc<FakeNetworkState> {
        &self.state
    }

    /// Stop all fake server tasks.
    pub async fn stop(mut self) {
        let _ = self.shutdown.send(true);
        for task in &mut self.tasks {
            task.abort();
        }
    }
}

/// Build resolver configuration pointing at the fake root server.
pub fn resolver_config(map: &AddressMap) -> IteratorConfig {
    IteratorConfig {
        root_servers: Some(vec![map.root_socket()]),
        nameserver_port: map.port(),
        case_randomization: false,
        qname_minimization: false,
        cookies: false,
        allow_ipv6: false,
        do_not_query: Vec::new(),
        ..IteratorConfig::default()
    }
}

fn unique_addresses(scenario: &Scenario) -> Result<Vec<IpAddr>, ReplayError> {
    let mut addresses = Vec::new();
    for range in &scenario.ranges {
        let Some(address) = range.address else {
            continue;
        };
        if !matches!(address, IpAddr::V4(_)) {
            return Err(ReplayError::Scenario {
                scenario: scenario.name.clone(),
                message: format!("IPv6 replay address {address} is not supported"),
            });
        }
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    if addresses.is_empty() {
        return Err(ReplayError::Scenario {
            scenario: scenario.name.clone(),
            message: "no RANGE ADDRESS directives".to_owned(),
        });
    }
    Ok(addresses)
}

fn root_address(scenario: &Scenario) -> IpAddr {
    scenario
        .ranges
        .iter()
        .find(|range| {
            range.entries.iter().any(|entry| {
                entry.first_reply().is_some_and(|reply| {
                    reply
                        .question
                        .first()
                        .is_some_and(|question| question.owner == ".")
                })
            })
        })
        .and_then(|range| range.address)
        .or_else(|| scenario.ranges.first().and_then(|range| range.address))
        .expect("unique_addresses rejects scenarios without ranges")
}

async fn serve_udp(
    address: IpAddr,
    socket: UdpSocket,
    ranges: Vec<Range>,
    map: AddressMap,
    state: Arc<FakeNetworkState>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut buffer = [0_u8; 4096];
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            received = socket.recv_from(&mut buffer) => {
                let Ok((length, peer)) = received else { break; };
                let Some(response) = response_for(
                    &buffer[..length], address, &ranges, &map, &state, false,
                ).await else { continue; };
                if socket.send_to(&response, peer).await.is_err() {
                    break;
                }
            }
        }
    }
}

async fn serve_tcp(
    address: IpAddr,
    listener: TcpListener,
    ranges: Vec<Range>,
    map: AddressMap,
    state: Arc<FakeNetworkState>,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            accepted = listener.accept() => {
                let Ok((mut stream, _)) = accepted else { break; };
                while let Ok(length) = stream.read_u16().await {
                    let mut buffer = vec![0_u8; usize::from(length)];
                    if stream.read_exact(&mut buffer).await.is_err() {
                        break;
                    }
                    let Some(response) = response_for(
                        &buffer, address, &ranges, &map, &state, true,
                    ).await else { break; };
                    let length = u16::try_from(response.len()).unwrap_or(u16::MAX);
                    if stream.write_all(&length.to_be_bytes()).await.is_err()
                        || stream.write_all(&response).await.is_err()
                    {
                        break;
                    }
                }
            }
        }
    }
}

async fn response_for(
    wire: &[u8],
    address: IpAddr,
    ranges: &[Range],
    map: &AddressMap,
    state: &FakeNetworkState,
    tcp: bool,
) -> Option<Vec<u8>> {
    let query = decode(wire).ok()?;
    state
        .record(QueryLog {
            address,
            name: query
                .queries
                .first()
                .map(|entry| entry.name().to_string())
                .unwrap_or_default(),
            rtype: query
                .queries
                .first()
                .map(|entry| entry.query_type().to_string())
                .unwrap_or_default(),
            class: query
                .queries
                .first()
                .map(|entry| entry.query_class().to_string())
                .unwrap_or_default(),
        })
        .await;
    let time = state.time().await;
    for range in ranges {
        if time < range.start || time > range.end {
            continue;
        }
        for entry in &range.entries {
            if !entry_matches(entry, &query) {
                continue;
            }
            let reply = select_reply(entry, tcp)?;
            return encode(&build_response(&query, reply, &entry.adjusts, map).ok()?).ok();
        }
    }
    None
}

fn select_reply(entry: &Entry, tcp: bool) -> Option<&Reply> {
    if tcp {
        entry
            .replies
            .iter()
            .find(|reply| !reply.flags.tc)
            .or_else(|| entry.replies.first())
    } else {
        entry.replies.first()
    }
}

fn entry_matches(entry: &Entry, query: &Message) -> bool {
    let Some(question) = entry.first_reply().and_then(|reply| reply.question.first()) else {
        return true;
    };
    let Some(query_question) = query.queries.first() else {
        return false;
    };
    let matches = entry.matches.iter().map(String::as_str).collect::<Vec<_>>();
    if matches.contains(&"all") {
        return true;
    }
    let check_name =
        matches.contains(&"qname") || matches.contains(&"subdomain") || matches.is_empty();
    if check_name && !name_matches(&question.owner, query_question.name(), &matches) {
        return false;
    }
    if (matches.contains(&"qtype") || matches.is_empty())
        && !question
            .rtype
            .eq_ignore_ascii_case(&query_question.query_type().to_string())
    {
        return false;
    }
    if matches.contains(&"qclass")
        && !question
            .class
            .eq_ignore_ascii_case(&query_question.query_class().to_string())
    {
        return false;
    }
    true
}

fn name_matches(expected: &str, actual: &Name, matches: &[&str]) -> bool {
    let expected = expected.trim_end_matches('.').to_ascii_lowercase();
    let actual = actual
        .to_string()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if actual == expected {
        return true;
    }
    matches.contains(&"subdomain") && actual.ends_with(&format!(".{expected}"))
}

fn build_response(
    query: &Message,
    reply: &Reply,
    adjusts: &[String],
    map: &AddressMap,
) -> Result<Message, ReplayError> {
    let mut response = Message::new(
        query.metadata.id,
        MessageType::Response,
        parse_op_code(&reply.op_code),
    );
    response.metadata.response_code = reply.rcode;
    response.metadata.authoritative = reply.flags.aa;
    response.metadata.truncation = reply.flags.tc;
    response.metadata.recursion_desired = reply.flags.rd;
    response.metadata.recursion_available = reply.flags.ra;
    response.metadata.authentic_data = reply.flags.ad;
    response.metadata.checking_disabled = reply.flags.cd;
    if query.edns.is_some() {
        response.edns = Some(Edns::new());
    }
    let copy_query = adjusts.iter().any(|adjust| adjust == "copy_query");
    let question = if copy_query {
        query.queries.first().cloned()
    } else {
        match reply.question.first() {
            Some(line) => Some(build_query(line)?),
            None => query.queries.first().cloned(),
        }
    };
    if let Some(question) = question {
        response.queries.push(question);
    }
    for (line, section) in reply
        .answer
        .iter()
        .map(|line| (line, 0))
        .chain(reply.authority.iter().map(|line| (line, 1)))
        .chain(reply.additional.iter().map(|line| (line, 2)))
    {
        let record = build_record(line, map)?;
        match section {
            0 => response.add_answer(record),
            1 => response.add_authority(record),
            _ => response.add_additional(record),
        };
    }
    Ok(response)
}

fn build_query(line: &RecordLine) -> Result<Query, ReplayError> {
    let name = parse_name(&line.owner)?;
    let rtype = parse_record_type(&line.rtype)?;
    let mut query = Query::query(name, rtype);
    query.set_query_class(parse_class(&line.class)?);
    Ok(query)
}

fn build_record(line: &RecordLine, map: &AddressMap) -> Result<Record, ReplayError> {
    let name = parse_name(&line.owner)?;
    let rtype = parse_record_type(&line.rtype)?;
    let class = parse_class(&line.class)?;
    let mut rdata_tokens = line.rdata.clone();
    if let Some(address) = rdata_tokens
        .first()
        .and_then(|token| token.parse::<IpAddr>().ok())
        && let Some(local) = map.local(address)
    {
        rdata_tokens[0] = local.to_string();
    }
    let data = RData::try_from_str(rtype, &rdata_tokens.join(" "))
        .map_err(|error| ReplayError::Message(error.to_string()))?;
    let mut record = Record::from_rdata(name, line.ttl.unwrap_or(3600), data);
    record.dns_class = class;
    Ok(record)
}

fn parse_name(value: &str) -> Result<Name, ReplayError> {
    Name::from_ascii(value).map_err(|error| ReplayError::Message(error.to_string()))
}

fn parse_record_type(value: &str) -> Result<RecordType, ReplayError> {
    RecordType::from_str(&value.to_ascii_uppercase())
        .map_err(|error| ReplayError::Message(error.to_string()))
}

fn parse_class(value: &str) -> Result<DNSClass, ReplayError> {
    DNSClass::from_str(&value.to_ascii_uppercase())
        .map_err(|error| ReplayError::Message(error.to_string()))
}

fn parse_op_code(value: &str) -> OpCode {
    match value.to_ascii_uppercase().as_str() {
        "STATUS" => OpCode::Status,
        "NOTIFY" => OpCode::Notify,
        "UPDATE" => OpCode::Update,
        _ => OpCode::Query,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_op_code;
    use dns_proto::OpCode;

    #[test]
    fn maps_replay_opcodes() {
        assert_eq!(parse_op_code("NOTIFY"), OpCode::Notify);
        assert_eq!(parse_op_code(""), OpCode::Query);
    }
}
