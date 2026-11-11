// Minimal loopback DNS load generator and authoritative mock for benchmarking
// dns-rs. Build with:
//   rustc --edition 2024 -O -o /tmp/dns-bench scripts/dns-bench.rs

use std::env;
use std::net::{SocketAddr, UdpSocket};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};

const QTYPE_A: u16 = 1;
const CLASS_IN: u16 = 1;

fn encode_name(out: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
}

fn build_queries(count: usize, zone: &str) -> Vec<Vec<u8>> {
    (0..count)
        .map(|i| {
            let name = format!("n{i:05}.{zone}");
            let mut packet = vec![
                0, 0, // id, patched per request
                0x01, 0x00, // RD
                0, 1, // QDCOUNT
                0, 0, // ANCOUNT
                0, 0, // NSCOUNT
                0, 1, // ARCOUNT: one OPT record
            ];
            encode_name(&mut packet, &name);
            packet.extend_from_slice(&QTYPE_A.to_be_bytes());
            packet.extend_from_slice(&CLASS_IN.to_be_bytes());
            // OPT: root name, type 41, UDP size 1232, TTL 0, empty rdata.
            packet.extend_from_slice(&[0, 0, 41, 0x04, 0xD0, 0, 0, 0, 0, 0, 0]);
            packet
        })
        .collect()
}

fn question_end(message: &[u8]) -> Option<usize> {
    let mut offset = 12;
    loop {
        let len = *message.get(offset)? as usize;
        offset += 1;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            offset += 1;
            break;
        }
        offset = offset.checked_add(len)?;
        if offset > message.len() {
            return None;
        }
    }
    offset.checked_add(4).filter(|end| *end <= message.len())
}

/// Answer queries until killed, stamping answers with `ttl` seconds.
///
/// A TTL of 0 makes the resolver's `cache_min_ttl` clamp keep the entry at 0,
/// so nothing is stored and every query is a genuine cache miss. Prints
/// `stats upstream_queries=N` on stdout every 250 ms so the runner can
/// snapshot the count around a measurement window.
fn serve(addr: SocketAddr, ttl: u32) -> ! {
    let socket = UdpSocket::bind(addr).unwrap_or_else(|e| {
        eprintln!("mock: bind {addr}: {e}");
        process::exit(1);
    });
    eprintln!("mock: listening on {addr} ttl={ttl}");
    let answered = Arc::new(AtomicU64::new(0));
    let reporter = Arc::clone(&answered);
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(250));
        println!("stats upstream_queries={}", reporter.load(Ordering::Relaxed));
    });
    let ttl_bytes = ttl.to_be_bytes();
    let mut buf = [0u8; 1500];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("mock: recv: {error}");
                continue;
            }
        };
        let Some(end) = question_end(&buf[..len]) else {
            continue;
        };
        let mut response = Vec::with_capacity(end + 16);
        response.extend_from_slice(&buf[..end]);
        response[2] = 0x84; // QR + AA
        response[3] = buf[3] & 0x01; // echo RD
        response[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        response[8..10].copy_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        response[10..12].copy_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        response.extend_from_slice(&[
            0xC0, 0x0C, // name pointer to the question
            0x00, 0x01, // A
            0x00, 0x01, // IN
        ]);
        response.extend_from_slice(&ttl_bytes);
        response.extend_from_slice(&[
            0x00, 0x04, // RDLENGTH
            192, 0, 2, 1,
        ]);
        let _ = socket.send_to(&response, peer);
        answered.fetch_add(1, Ordering::Relaxed);
    }
}

struct Config {
    target: SocketAddr,
    queries: Vec<Vec<u8>>,
    warmup: Duration,
    duration: Duration,
}

struct ThreadResult {
    samples: Vec<u64>,
    errors: u64,
    rcode_errors: u64,
    /// Measured responses that carried the AD bit (header byte 3, mask 0x20).
    authenticated: u64,
    sent: u64,
}

fn run_thread(config: &Config, id: usize, barrier: &Barrier) -> ThreadResult {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind client socket");
    socket
        .connect(config.target)
        .expect("connect client socket");
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .expect("read timeout");
    let mut seq = (id as u32) << 24;
    let total = config.warmup + config.duration;
    let mut samples = Vec::with_capacity(250_000);
    let mut errors = 0u64;
    let mut rcode_errors = 0u64;
    let mut authenticated = 0u64;
    let mut sent = 0u64;
    let mut buf = [0u8; 2048];

    let start = Instant::now();
    barrier.wait();
    loop {
        let elapsed = start.elapsed();
        if elapsed >= total {
            break;
        }
        seq = seq.wrapping_add(1);
        let packet = &config.queries[(seq as usize) % config.queries.len()];
        let id = seq as u16;
        let mut wire = packet.clone();
        wire[0..2].copy_from_slice(&id.to_be_bytes());
        sent += 1;
        if socket.send(&wire).is_err() {
            errors += 1;
            continue;
        }
        let sent = Instant::now();
        let received = match socket.recv(&mut buf) {
            Ok(len) => len,
            Err(_) => {
                errors += 1;
                continue;
            }
        };
        let rtt = sent.elapsed().as_nanos() as u64;
        if received < 12 || u16::from_be_bytes([buf[0], buf[1]]) != id || buf[2] & 0x80 == 0 {
            errors += 1;
            continue;
        }
        if buf[3] & 0x0F != 0 {
            rcode_errors += 1;
            continue;
        }
        if elapsed >= config.warmup {
            if buf[3] & 0x20 != 0 {
                authenticated += 1;
            }
            samples.push(rtt);
        }
    }
    ThreadResult {
        samples,
        errors,
        rcode_errors,
        authenticated,
        sent,
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((p / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn load(
    target: SocketAddr,
    names: usize,
    zone: &str,
    concurrency: usize,
    warmup: Duration,
    duration: Duration,
) -> ! {
    let queries = build_queries(names, zone);
    let config = Arc::new(Config {
        target,
        queries,
        warmup,
        duration,
    });
    let barrier = Arc::new(Barrier::new(concurrency + 1));
    let mut handles = Vec::with_capacity(concurrency);
    for id in 0..concurrency {
        let barrier = Arc::clone(&barrier);
        let config = Arc::clone(&config);
        handles.push(thread::spawn(move || run_thread(&config, id, &barrier)));
    }
    barrier.wait();
    let wall = Instant::now();
    let mut results = Vec::with_capacity(concurrency);
    for handle in handles {
        results.push(handle.join().expect("client thread panicked"));
    }
    let elapsed = wall.elapsed().as_secs_f64();
    let mut samples = Vec::new();
    let mut errors = 0u64;
    let mut rcode_errors = 0u64;
    let mut authenticated = 0u64;
    let mut sent = 0u64;
    for result in results {
        samples.extend(result.samples);
        errors += result.errors;
        rcode_errors += result.rcode_errors;
        authenticated += result.authenticated;
        sent += result.sent;
    }
    samples.sort_unstable();
    let count = samples.len() as f64;
    let qps = count / elapsed;
    println!(
        "RESULT concurrency={concurrency} samples={} qps={qps:.0} sent={sent} errors={errors} rcode={rcode_errors} ad={authenticated} p50_us={:.1} p75_us={:.1} p90_us={:.1} p95_us={:.1} p99_us={:.1} max_us={:.1}",
        samples.len(),
        percentile(&samples, 50.0) as f64 / 1000.0,
        percentile(&samples, 75.0) as f64 / 1000.0,
        percentile(&samples, 90.0) as f64 / 1000.0,
        percentile(&samples, 95.0) as f64 / 1000.0,
        percentile(&samples, 99.0) as f64 / 1000.0,
        *samples.last().unwrap_or(&0) as f64 / 1000.0,
    );
    process::exit(0);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!(
            "usage: dnsbench serve ADDR [TTL_SECS] | dnsbench load ADDR NAMES ZONE CONCURRENCY [WARMUP_SECS] [DURATION_SECS]"
        );
        process::exit(2);
    }
    match args[1].as_str() {
        "serve" => {
            let addr: SocketAddr = args[2].parse().expect("mock address");
            let ttl: u32 = args
                .get(3)
                .map_or(3600, |value| value.parse().expect("ttl"));
            serve(addr, ttl);
        }
        "load" => {
            let target: SocketAddr = args[2].parse().expect("target address");
            let names: usize = args[3].parse().expect("name count");
            let zone = &args[4];
            let concurrency: usize = args[5].parse().expect("concurrency");
            let warmup: u64 = args
                .get(6)
                .map_or(5, |value| value.parse().expect("warmup"));
            let duration: u64 = args
                .get(7)
                .map_or(10, |value| value.parse().expect("duration"));
            load(
                target,
                names,
                zone,
                concurrency,
                Duration::from_secs(warmup),
                Duration::from_secs(duration),
            );
        }
        other => {
            eprintln!("unknown mode {other}");
            process::exit(2);
        }
    }
}
