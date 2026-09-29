//! Rolling-window latency measurement and live-telemetry publishing for the
//! ingest pipeline.
//!
//! The serve plane cannot see inside the ingest task graph, so anything the
//! dashboard claims about a *live* pipeline has to be measured here and
//! published. This module is the only place in the codebase permitted to turn
//! ingest state into dashboard numbers, which keeps the fabrication risk
//! concentrated in one auditable file.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;

use ulpf_core::ingest::telemetry::IngestSnapshot;

/// Fixed-capacity ring of recent per-line parse latencies.
///
/// Fixed capacity on purpose: a `Vec` that grew without bound would leak
/// memory proportional to traffic on a process designed to run at line rate.
/// When the ring wraps, the oldest sample is overwritten, so the window
/// always describes the most recent N lines and never a lifetime average.
///
/// The window is guarded by a `Mutex` because percentiles need a consistent
/// snapshot of the ring, and a torn read would produce a p50 that never
/// corresponded to any real set of samples. Recording is one store under the
/// same lock, on the per-line path — a single uncontended `Mutex<usize>` write,
/// which is why the capacity is small and fixed.
pub struct LatencyWindow {
    /// Ring of microsecond samples; `None` marks a slot never written.
    ///
    /// Behind a `Mutex` for interior mutability, so a `&self` receiver can
    /// record from every parse worker without a `&mut` borrow. Percentiles
    /// need a consistent view of the whole ring, and the lock is what gives
    /// that: a torn read could pair a p50 and p99 from different ring states.
    samples: std::sync::Mutex<Vec<Option<f64>>>,
    /// Next write position.
    cursor: AtomicUsize,
    /// Count of samples recorded, saturating at the ring size.
    recorded: AtomicU64,
}

impl LatencyWindow {
    /// Build a window holding at most `capacity` samples.
    ///
    /// A zero capacity is coerced to 1: a window that can hold nothing could
    /// never produce a percentile, and a silent empty result would read as
    /// "measured, no data" rather than "misconfigured".
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            samples: std::sync::Mutex::new((0..capacity).map(|_| None).collect()),
            cursor: AtomicUsize::new(0),
            recorded: AtomicU64::new(0),
        }
    }

    /// Record one measurement. Called once per parsed line.
    pub fn record(&self, micros: f64) {
        // A poisoned lock means a panic while holding it. Fail open on the
        // sample rather than propagating that panic into the parse path:
        // losing one latency sample is strictly better than dropping a log
        // line, and the integrity guarantees do not depend on this gauge.
        let mut ring = match self.samples.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed) % ring.len();
        ring[idx] = Some(micros);
        // Saturating: the count is a sample tally, not a traffic counter, and
        // must not wrap into a plausible-looking small number.
        let _ = self
            .recorded
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some((v + 1).min(ring.len() as u64))
            });
    }

    /// Snapshot the window into ascending order.
    ///
    /// Public so a reporter holding several workers' windows can merge their
    /// samples. Each window is owned and written by exactly one worker, so the
    /// lock here is uncontended in the steady state; only the once-per-second
    /// aggregate takes it from a second thread.
    pub fn sorted(&self) -> Vec<f64> {
        let ring = match self.samples.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        ring.iter().filter_map(|s| *s).collect()
    }

    /// Median and 99th percentile over the window, or `None` when empty.
    ///
    /// Returns a pair so both figures always come from the same sample set —
    /// computing them against separately-sorted copies could otherwise pair a
    /// p50 from one window state with a p99 from another.
    pub fn percentiles(&self) -> (Option<f64>, Option<f64>, u64) {
        percentiles_over(&self.sorted())
    }
}

/// Percentiles over an arbitrary merged sample set.
///
/// Used both by a single window and by the reporter combining every worker's
/// window, so a merged multi-worker figure and a single-worker figure are
/// computed identically.
pub fn percentiles_over(sorted: &[f64]) -> (Option<f64>, Option<f64>, u64) {
    {
        let mut sorted = sorted.to_vec();
        let n = sorted.len();
        if n == 0 {
            return (None, None, 0);
        }
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let p50 = percentile_of(&sorted, 0.50);
        let p99 = percentile_of(&sorted, 0.99);
        (Some(p50), Some(p99), n as u64)
    }
}

/// Linear-interpolated percentile over an ascending-sorted slice.
fn percentile_of(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    if sorted.len() == 1 {
        return sorted[0];
    }
    let rank = q * (sorted.len() - 1) as f64;
    let lo = rank.floor() as usize;
    let hi = rank.ceil() as usize;
    if lo == hi {
        return sorted[lo];
    }
    let frac = rank - lo as f64;
    sorted[lo] * (1.0 - frac) + sorted[hi] * frac
}

/// Everything the ingest pipeline knows that a dashboard may legitimately
/// report, gathered at one instant so the published snapshot is internally
/// consistent.
///
/// Counters are read individually and a flush can land between two reads. That
/// is accepted: these are live gauges read out of band, not a transaction. A
/// brief inconsistency of one line is preferable to taking a lock across the
/// reporting path.
pub struct TelemetryPublisher {
    /// Line count for computing a rate between two reports.
    last_ingested: AtomicU64,
    /// Clock at the previous report, for the same purpose.
    last_report: std::sync::Mutex<Instant>,
    /// Cached EPS from the previous interval, so an unchanged counter reports
    /// `0.0` (traffic observed, rate zero) instead of losing the measurement.
    last_eps: AtomicU64,
    started: Instant,
}

impl Default for TelemetryPublisher {
    fn default() -> Self {
        Self {
            last_ingested: AtomicU64::new(0),
            last_report: std::sync::Mutex::new(Instant::now()),
            last_eps: AtomicU64::new(0),
            started: Instant::now(),
        }
    }
}

impl TelemetryPublisher {
    /// Build a publisher. Equivalent to [`TelemetryPublisher::default`];
    /// kept as a named constructor because the call site reads better with it.
    pub fn new() -> Self {
        Self::default()
    }

    /// Milliseconds since this publisher was created — the monotonic clock
    /// domain shared by every snapshot this process writes.
    pub fn monotonic_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Build a snapshot from the current counters.
    ///
    /// `observed_eps` is passed in rather than computed here because only the
    /// caller knows the reporting interval it just measured over.
    pub fn snapshot(
        &self,
        observed_eps: Option<f64>,
        lru: Option<(f64, u64)>,
        queue_depth: Option<usize>,
        queue_capacity: Option<usize>,
        dropped: Option<u64>,
        total_ingested: Option<u64>,
        total_parsed: Option<u64>,
        total_blocks: Option<u64>,
        total_anomalies: Option<u64>,
        vendor_counts: std::collections::BTreeMap<String, u64>,
        latency: (Option<f64>, Option<f64>, u64),
    ) -> IngestSnapshot {
        let (p50, p99, samples) = latency;
        IngestSnapshot {
            monotonic_ms: self.monotonic_ms(),
            unix_ms: chrono::Utc::now().timestamp_millis(),
            eps: observed_eps,
            latency_p50_micros: p50,
            latency_p99_micros: p99,
            latency_samples: samples,
            lru_hit_rate: lru.map(|(rate, _)| rate),
            lru_lookups: lru.map(|(_, lookups)| lookups),
            queue_depth,
            queue_capacity,
            dropped_count: dropped,
            total_ingested,
            total_parsed,
            total_blocks,
            total_anomalies,
            vendor_counts,
            running: true,
        }
    }

    /// Rate of change in `ingested` since the previous call, over the elapsed
    /// wall time between them.
    ///
    /// Returns `None` on the very first call: there is no previous sample, so
    /// no rate has been measured yet. Returning a number there would be
    /// inventing one — and specifically would divide the whole lifetime count
    /// by the microseconds since construction, yielding an absurd EPS.
    pub fn observe_ingested(&self, ingested: u64) -> Option<f64> {
        let mut last_time = match self.last_report.lock() {
            Ok(guard) => guard,
            // Poisoned: we cannot know the interval, so we cannot know the
            // rate. Report no measurement rather than a wrong one.
            Err(_) => return None,
        };
        let now = Instant::now();
        let elapsed = now.duration_since(*last_time).as_secs_f64();
        let previous = self.last_ingested.swap(ingested, Ordering::Relaxed);
        *last_time = now;

        // `last_report` starts at construction, so a small elapsed time means
        // this is the first observation rather than a real sampling interval.
        // A reporting interval is ~1s; anything near zero is not one.
        if elapsed <= 1e-3 {
            return None;
        }
        // `ingested` is cumulative and monotonic, but a counter that went
        // backwards (restart, reset) would otherwise produce a negative rate.
        let delta = ingested.saturating_sub(previous);
        let rate = delta as f64 / elapsed;
        self.last_eps.store(rate as u64, Ordering::Relaxed);
        Some(rate)
    }
}

/// Shared handle, cheap to clone into every parse worker.
pub type SharedTelemetry = Arc<TelemetryPublisher>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_window_reports_no_measurement() {
        let w = LatencyWindow::new(8);
        let (p50, p99, n) = w.percentiles();
        assert_eq!((p50, p99, n), (None, None, 0));
    }

    #[test]
    fn test_single_sample_is_both_percentiles() {
        let w = LatencyWindow::new(8);
        w.record(5.0);
        let (p50, p99, n) = w.percentiles();
        assert_eq!((p50, p99, n), (Some(5.0), Some(5.0), 1));
    }

    #[test]
    fn test_percentiles_over_known_distribution() {
        let w = LatencyWindow::new(100);
        for i in 1..=100u32 {
            w.record(f64::from(i));
        }
        let (p50, p99, n) = w.percentiles();
        assert_eq!(n, 100);
        let p50 = p50.expect("measured");
        let p99 = p99.expect("measured");
        // Median of 1..=100 sits between 50 and 51.
        assert!((49.0..=52.0).contains(&p50), "p50 was {p50}");
        // p99 sits between 99 and 100.
        assert!((98.0..=100.0).contains(&p99), "p99 was {p99}");
    }

    /// The ring must not grow without bound, and must describe the *most
    /// recent* samples once it wraps — a lifetime average would be a
    /// meaningless blend of a slow start and a fast steady state.
    #[test]
    fn test_ring_wraps_and_reports_recent_samples() {
        let w = LatencyWindow::new(4);
        for _ in 0..10 {
            w.record(100.0);
        }
        for _ in 0..4 {
            w.record(2.0);
        }
        let (p50, p99, n) = w.percentiles();
        assert_eq!(n, 4, "sample count must cap at the ring size");
        assert_eq!(p50, Some(2.0), "old samples must be evicted, not averaged");
        assert_eq!(p99, Some(2.0));
    }

    #[test]
    fn test_zero_capacity_is_coerced_not_dead() {
        let w = LatencyWindow::new(0);
        w.record(3.0);
        let (p50, _, n) = w.percentiles();
        assert_eq!((p50, n), (Some(3.0), 1));
    }

    #[test]
    fn test_first_rate_observation_has_no_measurement() {
        let p = TelemetryPublisher::new();
        assert_eq!(
            p.observe_ingested(100),
            None,
            "a first sample has no interval to divide by"
        );
    }

    /// A counter that goes backwards must not yield a negative rate.
    #[test]
    fn test_counter_reset_yields_zero_not_negative() {
        let p = TelemetryPublisher::new();
        p.observe_ingested(1_000);
        std::thread::sleep(std::time::Duration::from_millis(5));
        let rate = p.observe_ingested(10).expect("second observation");
        assert_eq!(rate, 0.0, "a reset counter reads as zero, never negative");
    }

    #[test]
    fn test_snapshot_carries_measured_values_not_defaults() {
        let p = TelemetryPublisher::new();
        let window = LatencyWindow::new(16);
        window.record(4.0);
        let snap = p.snapshot(
            Some(1234.0),
            Some((0.875, 800)),
            Some(3),
            Some(50_000),
            Some(0),
            Some(10),
            Some(10),
            Some(1),
            Some(0),
            Default::default(),
            window.percentiles(),
        );
        assert_eq!(snap.eps, Some(1234.0));
        assert_eq!(snap.latency_p50_micros, Some(4.0));
        assert_eq!(snap.lru_hit_rate, Some(0.875));
        assert_eq!(snap.lru_lookups, Some(800), "the ratio must be auditable");
        assert_eq!(snap.queue_capacity, Some(50_000));
        assert!(snap.running);
    }

    /// Nothing measured must surface as null, never as a plausible constant.
    #[test]
    fn test_unmeasured_fields_are_null() {
        let p = TelemetryPublisher::new();
        let snap = p.snapshot(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Default::default(),
            (None, None, 0),
        );
        assert_eq!(snap.eps, None);
        assert_eq!(snap.lru_hit_rate, None);
        assert_eq!(snap.queue_depth, None);
        assert_eq!(snap.latency_p50_micros, None);
    }
}
