//! Per-phase query timing behind the `phase-stats` feature.
//!
//! Every phase of a query is timed with a [`PhaseTimer`] and summed into
//! process-wide counters. A reporter thread prints `stats phases ...` on
//! stdout every 250 ms, which `scripts/bench-loopback.sh` brackets around its
//! load window the same way it reads the mock authority's
//! `stats upstream_queries=N`. Dividing each phase total by the queries sent
//! gives the per-query cost of that phase, so a regression can be attributed
//! to a stage of the pipeline without a profiler.
//!
//! Without the feature [`PhaseTimer`] is a zero-sized type whose methods
//! inline away, so production builds pay nothing: no clock reads, no
//! counters, no reporter.

/// Stages of one query, in pipeline order.
///
/// `Queue` and `Send` are recorded by the UDP listener around the receive and
/// send syscalls; the rest are recorded inside the query pipeline. Not every
/// query visits every phase - a cache hit never reaches `Coalesce` or
/// `Upstream` - so the reporter emits totals only and the runner divides by
/// the queries it sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Datagram received, waiting for the handler task to start running.
    Queue,
    /// Message decode plus admission checks: ACL, rate limit, per-client
    /// concurrency, and local-zone answers, up to the cache probe.
    Decode,
    /// Message-cache probe (`get`, plus the serve-expired `get_stale` probe).
    Lookup,
    /// Single-flight registry: registering as a leader, or a follower waiting
    /// for the leader's answer.
    Coalesce,
    /// Recursive resolution against upstream nameservers (leaders only).
    Upstream,
    /// Building the reply: validation policy, rebinding filter, encoding,
    /// cache insert, and per-client patching.
    Finalize,
    /// The `sendto` syscall that returns the reply to the client (UDP only).
    Send,
}

#[cfg(feature = "phase-stats")]
impl Phase {
    /// Number of phases reported, in [`Phase::ALL`] order.
    const COUNT: usize = 7;

    /// Every phase, in report order.
    const ALL: [Phase; Self::COUNT] = [
        Phase::Queue,
        Phase::Decode,
        Phase::Lookup,
        Phase::Coalesce,
        Phase::Upstream,
        Phase::Finalize,
        Phase::Send,
    ];

    /// Stable report key for this phase.
    fn key(self) -> &'static str {
        match self {
            Phase::Queue => "queue",
            Phase::Decode => "decode",
            Phase::Lookup => "lookup",
            Phase::Coalesce => "coalesce",
            Phase::Upstream => "upstream",
            Phase::Finalize => "finalize",
            Phase::Send => "send",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// Times one phase of a query.
///
/// Call [`PhaseTimer::end`] exactly once, at the point the phase finishes;
/// starting the next phase's timer before ending this one would double-count
/// the overlapping wall time.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PhaseTimer {
    #[cfg(feature = "phase-stats")]
    phase: Phase,
    #[cfg(feature = "phase-stats")]
    started: Instant,
}

impl PhaseTimer {
    /// Start timing `phase`.
    #[cfg(feature = "phase-stats")]
    #[inline(always)]
    pub(crate) fn start(phase: Phase) -> Self {
        Self {
            phase,
            started: Instant::now(),
        }
    }

    /// Start timing `phase`. Compiles to a no-op without `phase-stats`.
    #[cfg(not(feature = "phase-stats"))]
    #[inline(always)]
    pub(crate) fn start(_phase: Phase) -> Self {
        Self {}
    }

    /// Record the elapsed time for this phase.
    ///
    /// A batched UDP receive opens one `Queue` timer for the whole harvest
    /// and calls this once per datagram: each call records that query's own
    /// wait since the receive syscall, so its position inside the batch is
    /// attributed to `Queue` instead of vanishing between phases. Any other
    /// phase must call `end` exactly once (see [`PhaseTimer`]).
    #[cfg(feature = "phase-stats")]
    #[inline(always)]
    pub(crate) fn end(&self) {
        record(self.phase, self.started.elapsed());
    }

    /// Discard the timer. Compiles to a no-op without `phase-stats`.
    #[cfg(not(feature = "phase-stats"))]
    #[inline(always)]
    pub(crate) fn end(&self) {}
}

#[cfg(feature = "phase-stats")]
use std::cell::Cell;
#[cfg(feature = "phase-stats")]
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
#[cfg(feature = "phase-stats")]
use std::thread;
#[cfg(feature = "phase-stats")]
use std::time::{Duration, Instant};

/// Counter shards. Each recording thread claims one on first use, so
/// concurrent workers never fight over the same cache line: a contended
/// `fetch_add` would land between two phases and inflate exactly the gap
/// this instrumentation exists to measure.
#[cfg(feature = "phase-stats")]
const SHARD_COUNT: usize = 32;

/// Nanoseconds recorded per phase within one shard.
#[cfg(feature = "phase-stats")]
type PhaseSums = [AtomicU64; Phase::COUNT];

/// One shard, padded to a cache line so adjacent shards never share one.
#[cfg(feature = "phase-stats")]
#[repr(C, align(64))]
struct Shard {
    sums: PhaseSums,
}

#[cfg(feature = "phase-stats")]
impl Shard {
    const fn new() -> Self {
        Self {
            sums: [const { AtomicU64::new(0) }; Phase::COUNT],
        }
    }
}

/// Process-wide phase totals, summed across every shard on read.
#[cfg(feature = "phase-stats")]
static SHARDS: [Shard; SHARD_COUNT] = [const { Shard::new() }; SHARD_COUNT];

/// Next shard to hand out; threads claim one the first time they record.
#[cfg(feature = "phase-stats")]
static NEXT_SHARD: AtomicUsize = AtomicUsize::new(0);

// This thread's shard, assigned on first use.
#[cfg(feature = "phase-stats")]
thread_local! {
    static SHARD: Cell<usize> = const { Cell::new(usize::MAX) };
}

/// The shard owned by the calling thread, claimed on first use.
#[cfg(feature = "phase-stats")]
fn shard_index() -> usize {
    SHARD.with(|index| {
        let claimed = index.get();
        if claimed == usize::MAX {
            let assigned = NEXT_SHARD.fetch_add(1, Ordering::Relaxed) % SHARD_COUNT;
            index.set(assigned);
            assigned
        } else {
            claimed
        }
    })
}

/// Add one observation of `phase` to the calling thread's shard.
#[cfg(feature = "phase-stats")]
#[inline(always)]
fn record(phase: Phase, elapsed: Duration) {
    let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
    SHARDS[shard_index()].sums[phase.index()].fetch_add(nanos, Ordering::Relaxed);
}

/// Total nanoseconds recorded for each phase since process start.
#[cfg(feature = "phase-stats")]
fn snapshot() -> [u64; Phase::COUNT] {
    let mut totals = [0_u64; Phase::COUNT];
    for shard in &SHARDS {
        for (index, sum) in shard.sums.iter().enumerate() {
            totals[index] += sum.load(Ordering::Relaxed);
        }
    }
    totals
}

/// Render the reporter line for one snapshot. The bench runner parses this
/// exact shape (`sed -n 's/^stats phases //p'`), so the format is a contract
/// with `scripts/bench-loopback.sh`.
#[cfg(feature = "phase-stats")]
fn report_line(totals: &[u64; Phase::COUNT]) -> String {
    use std::fmt::Write;

    let mut line = String::from("stats phases");
    for (phase, total) in Phase::ALL.iter().zip(totals) {
        let _ = write!(line, " {}_ns={total}", phase.key());
    }
    line
}

/// Print `stats phases ...` on stdout every 250 ms until the process exits,
/// so the runner can bracket a measurement window. Dropping the join handle
/// detaches the thread; it exits with the process.
#[cfg(feature = "phase-stats")]
pub fn spawn_reporter() {
    thread::spawn(|| {
        loop {
            thread::sleep(Duration::from_millis(250));
            println!("{}", report_line(&snapshot()));
        }
    });
}

#[cfg(all(test, feature = "phase-stats"))]
mod tests {
    use super::{Phase, PhaseTimer, record, report_line, snapshot};
    use std::time::Duration;

    /// A finished timer moves its phase total forward by at least the time
    /// the timer was open.
    #[test]
    fn ended_timers_accumulate() {
        let phase = Phase::Finalize;
        let before = snapshot()[phase.index()];
        let timer = PhaseTimer::start(phase);
        std::thread::sleep(Duration::from_millis(2));
        timer.end();
        let after = snapshot()[phase.index()];
        assert!(
            after - before >= 2_000_000,
            "expected at least 2 ms recorded, got {} ns",
            after - before
        );
    }

    /// Direct `record` calls land in the calling thread's shard and show up
    /// in the summed snapshot.
    #[test]
    fn records_accumulate_across_shards() {
        let phase = Phase::Send;
        let before = snapshot()[phase.index()];
        record(phase, Duration::from_micros(50));
        record(phase, Duration::from_micros(25));
        let after = snapshot()[phase.index()];
        assert_eq!(after - before, 75_000);
    }

    /// A batched receive ends one `Queue` timer once per datagram; each
    /// call records the wait up to that moment, so summed totals cover
    /// every datagram's position in the batch.
    #[test]
    fn repeated_ends_record_each_wait() {
        let phase = Phase::Queue;
        let before = snapshot()[phase.index()];
        let timer = PhaseTimer::start(phase);
        std::thread::sleep(Duration::from_millis(2));
        timer.end();
        std::thread::sleep(Duration::from_millis(2));
        timer.end();
        let after = snapshot()[phase.index()];
        assert!(
            after - before >= 6_000_000,
            "expected the two ends to cover at least 6 ms (2 ms + 4 ms), got {} ns",
            after - before
        );
    }

    /// The runner parses this shape; keep it stable.
    #[test]
    fn report_line_shape() {
        let mut totals = [0_u64; Phase::COUNT];
        totals[Phase::Queue.index()] = 42;
        assert_eq!(
            report_line(&totals),
            "stats phases queue_ns=42 decode_ns=0 lookup_ns=0 coalesce_ns=0 \
             upstream_ns=0 finalize_ns=0 send_ns=0"
        );
    }
}
