use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// A measured snapshot of the live ingest pipeline, published by the ingest
/// process and read by the out-of-band serve plane.
///
/// # Why a file
///
/// `ulpf ingest` and `ulpf serve` are separate processes. The counters that
/// make honest telemetry possible — queue depth, dropped lines, parser LRU
/// hit rate, per-line latencies — exist only inside the ingest task graph and
/// are not reachable from a different process. A sidecar file is the cheapest
/// boundary that stays inside the air-gapped invariant: no socket, no
/// dependency, no network.
///
/// # Honesty contract
///
/// Two rules govern this type, and both exist to stop a stale or absent
/// reading from being mistaken for a live one:
///
/// 1. **Absence is null, never a default.** A field that could not be
///    measured is `null`. It is never `0`, and never a plausible-looking
///    constant. A consumer that wants a number must handle `null` rather than
///    being handed an invented one.
/// 2. **Staleness is visible.** [`IngestSnapshot::monotonic_ms`] stamps the
///    write, and [`IngestSnapshot::age`] reports how long ago it happened. A
///    reader decides what counts as too old; see
///    [`crate::ingest::telemetry::DEFAULT_STALE_AFTER_MS`] for the shipped
///    default. Serving a stale reading is the caller's choice, made
///    knowingly — not a silent default.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct IngestSnapshot {
    /// Monotonic milliseconds since process start, stamped at write time.
    ///
    /// Monotonic rather than wall-clock so a clock adjustment cannot make a
    /// fresh reading look ancient. It is only meaningful relative to another
    /// reading from the same ingest process, which is exactly the comparison a
    /// reader makes.
    #[serde(default)]
    pub monotonic_ms: u64,
    /// Unix milliseconds when the snapshot was written. For humans and log
    /// correlation, not for staleness decisions.
    #[serde(default)]
    pub unix_ms: i64,

    /// Measured events per second, or `null` when no traffic has been seen.
    ///
    /// Measured as a rate over the reporting interval. `null` and `0` are
    /// different: `0` means traffic was observed and the rate was genuinely
    /// zero, `null` means there is no measurement yet.
    #[serde(default)]
    pub eps: Option<f64>,

    /// Median per-line parse latency over the rolling window, in microseconds.
    #[serde(default)]
    pub latency_p50_micros: Option<f64>,
    /// 99th percentile of the same window, in microseconds.
    #[serde(default)]
    pub latency_p99_micros: Option<f64>,
    /// How many samples the latency window currently holds.
    #[serde(default)]
    pub latency_samples: u64,

    /// Parser signature-cache hit ratio, from the real `LruStats`.
    #[serde(default)]
    pub lru_hit_rate: Option<f64>,
    /// Total cache lookups behind `lru_hit_rate`, so the ratio is auditable.
    #[serde(default)]
    pub lru_lookups: Option<u64>,

    /// Messages currently queued in the bounded ingest queue.
    #[serde(default)]
    pub queue_depth: Option<usize>,
    /// Configured bound on `queue_depth`.
    #[serde(default)]
    pub queue_capacity: Option<usize>,
    /// Cumulative lines shed by the drop-newest policy, all sources.
    #[serde(default)]
    pub dropped_count: Option<u64>,

    /// Cumulative lines accepted off the socket.
    #[serde(default)]
    pub total_ingested: Option<u64>,
    /// Cumulative lines normalized to OCSF.
    #[serde(default)]
    pub total_parsed: Option<u64>,
    /// Cumulative Merkle blocks anchored.
    #[serde(default)]
    pub total_blocks: Option<u64>,
    /// Cumulative Drain anomalies observed.
    #[serde(default)]
    pub total_anomalies: Option<u64>,

    /// Per-vendor parsed counts since process start.
    ///
    /// Counts rather than percentages: percentages need a denominator that
    /// may not be the whole corpus, and a percentage with no stated base is
    /// exactly the kind of number that misleads. A `BTreeMap` so the snapshot
    /// is byte-stable across writes, which makes diffing two snapshots
    /// meaningful.
    #[serde(default)]
    pub vendor_counts: BTreeMap<String, u64>,

    /// Set while the writing process is alive; cleared on a clean shutdown so
    /// a reader can tell "ingest stopped" from "ingest is idle but healthy".
    #[serde(default)]
    pub running: bool,
}

/// A snapshot older than this is treated as not-current by default.
///
/// Chosen to be several dashboard poll intervals (the UI polls ~1s) but well
/// under the batch flush interval times a few, so a momentarily slow write
/// does not blank the dashboard while a genuinely stopped ingest does.
pub const DEFAULT_STALE_AFTER_MS: u64 = 5_000;

/// Where the snapshot is written.
///
/// Defaults to a sibling of the ledger so ingest and serve derive the same
/// path from the same `--data-dir`-style inputs without either needing to know
/// about the other.
pub fn default_snapshot_path(ledger_path: &Path) -> PathBuf {
    ledger_path
        .parent()
        .unwrap_or_else(|| Path::new("data"))
        .join("live_telemetry.json")
}

/// Read the live snapshot, if one exists and parses.
///
/// Returns `Ok(None)` when the file is absent — an ingest process that has not
/// run yet is normal, not an error. A file that exists but is corrupt returns
/// an error, because silently treating unparseable telemetry as "no telemetry"
/// would hide a real fault.
pub fn read_snapshot(path: &Path) -> io::Result<Option<IngestSnapshot>> {
    match std::fs::read_to_string(path) {
        Ok(raw) => match serde_json::from_str::<IngestSnapshot>(&raw) {
            Ok(snap) => Ok(Some(snap)),
            Err(e) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("live telemetry at {} is unreadable: {e}", path.display()),
            )),
        },
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Write the snapshot atomically: write a temp file, then rename over the
/// target.
///
/// Rename within a directory is atomic on POSIX, so a reader polling the path
/// sees either the previous complete snapshot or the new complete one — never
/// a half-written file. A plain `write` would let the serve plane parse a
/// truncated document and, per `read_snapshot`, surface a spurious corruption
/// error on every poll during a write.
pub fn write_snapshot(path: &Path, snap: &IngestSnapshot) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let json = serde_json::to_vec_pretty(snap)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, &json)?;
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            // Best-effort cleanup so a failed write does not leave a stale
            // temp file behind for the next tick to trip over.
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

impl IngestSnapshot {
    /// Age of this snapshot relative to `now_ms` (a monotonic reading taken by
    /// the same ingest process's clock domain).
    ///
    /// Saturates at zero rather than wrapping: a snapshot stamped slightly
    /// ahead of our own reading — possible if the two clocks are sampled a
    /// moment apart — is treated as brand new, not as 2^64 milliseconds old.
    pub fn age(&self, now_ms: u64) -> u64 {
        now_ms.saturating_sub(self.monotonic_ms)
    }

    /// Whether this snapshot is still current enough to report as live.
    pub fn is_fresh(&self, now_ms: u64, stale_after_ms: u64) -> bool {
        self.age(now_ms) <= stale_after_ms
    }

    /// This snapshot with every live gauge cleared, keeping the structural
    /// and cumulative fields.
    ///
    /// Used when a reader has decided a snapshot is not current. Deliberately
    /// separate from [`IngestSnapshot::nulled_if_stale`]: that method judges
    /// freshness with a monotonic clock read in the *same* process, which
    /// cannot work here — the serve plane and the ingest plane do not share a
    /// monotonic epoch, so the serve plane must make the freshness decision
    /// itself and then call this.
    ///
    /// `vendor_counts` and the cumulative totals are retained because they are
    /// not live gauges: they describe everything the ingest process saw over
    /// its lifetime, so a stale reading of them is still true, just not
    /// current. Everything that describes *right now* is cleared.
    pub fn without_live_gauges(&self) -> IngestSnapshot {
        IngestSnapshot {
            monotonic_ms: self.monotonic_ms,
            unix_ms: self.unix_ms,
            running: false,
            vendor_counts: self.vendor_counts.clone(),
            total_ingested: self.total_ingested,
            total_parsed: self.total_parsed,
            total_blocks: self.total_blocks,
            total_anomalies: self.total_anomalies,
            ..IngestSnapshot::default()
        }
    }

    /// Drop every measurement that cannot be trusted because the snapshot is
    /// stale, keeping the structural fields so a reader can still show *that*
    /// ingest existed and what it wrote.
    ///
    /// Only usable when `now_ms` comes from the same monotonic clock domain as
    /// [`IngestSnapshot::monotonic_ms`] — i.e. in the writing process. A reader
    /// in another process must use [`IngestSnapshot::without_live_gauges`]
    /// after its own freshness check.
    pub fn nulled_if_stale(&self, now_ms: u64, stale_after_ms: u64) -> IngestSnapshot {
        if self.is_fresh(now_ms, stale_after_ms) {
            return self.clone();
        }
        self.without_live_gauges()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("ulpf-telemetry-{}-{}", name, std::process::id()));
        p
    }

    #[test]
    fn test_absent_snapshot_is_none_not_error() {
        let path = tmp_path("absent");
        let _ = std::fs::remove_file(&path);
        assert_eq!(read_snapshot(&path).unwrap(), None);
    }

    #[test]
    fn test_roundtrip_preserves_nulls() {
        let path = tmp_path("roundtrip");
        let snap = IngestSnapshot {
            monotonic_ms: 1_234,
            unix_ms: 1_700_000_000_000,
            eps: Some(1_234.5),
            latency_p50_micros: None,
            lru_hit_rate: Some(0.91),
            vendor_counts: BTreeMap::from([("cisco_asa".to_string(), 7u64)]),
            running: true,
            ..IngestSnapshot::default()
        };
        write_snapshot(&path, &snap).unwrap();
        let back = read_snapshot(&path).unwrap().expect("snapshot present");
        assert_eq!(back, snap, "nulls must survive the round trip as nulls");
        assert_eq!(back.latency_p50_micros, None);
        assert!(!back.vendor_counts.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_corrupt_snapshot_is_an_error_not_silence() {
        let path = tmp_path("corrupt");
        std::fs::write(&path, b"{ this is not json").unwrap();
        let err = read_snapshot(&path).expect_err("corrupt telemetry must not read as absent");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_write_leaves_no_temp_file() {
        let path = tmp_path("notemp");
        write_snapshot(&path, &IngestSnapshot::default()).unwrap();
        assert!(path.exists());
        let tmp = path.with_extension("json.tmp");
        assert!(!tmp.exists(), "atomic rename must not leave a temp file");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_stale_snapshot_nulls_measurements_but_keeps_structure() {
        let snap = IngestSnapshot {
            monotonic_ms: 1_000,
            eps: Some(500.0),
            lru_hit_rate: Some(0.9),
            queue_depth: Some(12),
            running: true,
            vendor_counts: BTreeMap::from([("fortigate".to_string(), 3u64)]),
            ..IngestSnapshot::default()
        };

        // Fresh: everything survives.
        let fresh = snap.nulled_if_stale(1_500, 5_000);
        assert_eq!(fresh.eps, Some(500.0));
        assert_eq!(fresh.queue_depth, Some(12));
        assert!(fresh.running);

        // Stale: measurements are nulled, provenance is kept.
        let stale = snap.nulled_if_stale(99_000, 5_000);
        assert_eq!(stale.eps, None, "a stale EPS must not be reported as live");
        assert_eq!(stale.lru_hit_rate, None);
        assert_eq!(stale.queue_depth, None);
        assert!(!stale.running, "a stale snapshot is not a running pipeline");
        assert_eq!(
            stale.vendor_counts, snap.vendor_counts,
            "vendor counts are cumulative, not a live gauge, so they persist"
        );
        assert_eq!(stale.unix_ms, snap.unix_ms, "provenance is retained");
    }

    /// Regression guard: a stale snapshot must not keep serving its live
    /// gauges. This was a real bug — the serve plane called
    /// `nulled_if_stale(0, 0)`, which evaluates as *fresh* (age saturates to
    /// zero against a `now` of 0), so the "clear the gauges" branch was
    /// unreachable and a stopped pipeline kept reporting its last EPS and
    /// latency as though they were current.
    #[test]
    fn test_without_live_gauges_clears_them() {
        let snap = IngestSnapshot {
            monotonic_ms: 1_000,
            unix_ms: 1_700_000_000_000,
            eps: Some(500.0),
            latency_p50_micros: Some(4.0),
            latency_p99_micros: Some(9.0),
            latency_samples: 4_096,
            lru_hit_rate: Some(0.9),
            lru_lookups: Some(100),
            queue_depth: Some(12),
            queue_capacity: Some(50_000),
            dropped_count: Some(0),
            total_ingested: Some(900),
            total_parsed: Some(900),
            total_blocks: Some(3),
            total_anomalies: Some(1),
            vendor_counts: BTreeMap::from([("cisco_asa".to_string(), 9u64)]),
            running: true,
        };

        let cleared = snap.without_live_gauges();

        // Everything describing "right now" is gone.
        assert_eq!(cleared.eps, None);
        assert_eq!(cleared.latency_p50_micros, None);
        assert_eq!(cleared.latency_p99_micros, None);
        assert_eq!(cleared.latency_samples, 0);
        assert_eq!(cleared.lru_hit_rate, None);
        assert_eq!(cleared.lru_lookups, None);
        assert_eq!(cleared.queue_depth, None);
        assert_eq!(cleared.queue_capacity, None);
        assert_eq!(cleared.dropped_count, None);
        assert!(
            !cleared.running,
            "a cleared snapshot is not a running pipeline"
        );

        // Cumulative facts survive: they are still true, just not current.
        assert_eq!(cleared.total_ingested, Some(900));
        assert_eq!(cleared.total_blocks, Some(3));
        assert_eq!(cleared.vendor_counts, snap.vendor_counts);

        // And it must not equal the original — the whole point is that it
        // differs.
        assert_ne!(cleared, snap);
    }

    /// `nulled_if_stale` is only valid within the writing process's clock
    /// domain. Against a foreign `now` it degenerates, which is exactly why
    /// cross-process readers must use `without_live_gauges` instead. Pin the
    /// behaviour so nobody reaches for it by mistake.
    #[test]
    fn test_nulled_if_stale_is_unusable_across_processes() {
        let snap = IngestSnapshot {
            monotonic_ms: 10_000,
            eps: Some(1.0),
            ..IngestSnapshot::default()
        };
        // A `now` from a different epoch (starts near zero) looks "fresh"
        // because age saturates at zero, so the gauges are NOT cleared. This
        // is documented, and the reason `without_live_gauges` exists.
        assert_eq!(snap.nulled_if_stale(0, 0).eps, Some(1.0));
        // Within the same domain, staleness clears as intended.
        assert_eq!(snap.nulled_if_stale(99_000, 5_000).eps, None);
    }

    #[test]
    fn test_age_saturates_instead_of_wrapping() {
        let snap = IngestSnapshot {
            monotonic_ms: 10_000,
            ..IngestSnapshot::default()
        };
        // A snapshot stamped slightly ahead of our reading is "new", not
        // ~1.8e19 ms old.
        assert_eq!(snap.age(9_000), 0);
        assert_eq!(snap.age(13_000), 3_000);
        assert!(snap.is_fresh(13_000, 5_000));
        assert!(!snap.is_fresh(20_000, 5_000));
    }
}
