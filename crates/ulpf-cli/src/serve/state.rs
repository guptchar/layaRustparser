use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use ulpf_ai::drain::AlertSeverity;
use ulpf_ai::onboarder::DynamicParserRegistry;
use ulpf_core::ingest::telemetry::{
    default_snapshot_path, read_snapshot, IngestSnapshot, DEFAULT_STALE_AFTER_MS,
};
use ulpf_integrity::batcher::BatchAccumulator;
use ulpf_integrity::storage::read_parquet_file;
use ulpf_integrity::tamper::verify_block_with_ledger;

use crate::serve::metrics_cache::{
    fingerprint_ledger, CorpusAggregates, CorpusCache, MetricsCache, DEFAULT_METRICS_TTL_MS,
};

/// A security or system alert presented to the SOC feed.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertItem {
    pub id: String,
    pub alert_type: String,
    pub severity: AlertSeverity,
    pub timestamp: i64,
    pub title: String,
    pub details: String,
    pub block_id: Option<u64>,
    pub leaf_index: Option<u32>,
}

/// Provenance for the live-pipeline half of the metrics response.
///
/// The dashboard needs to distinguish "measured", "idle", and "ingest is not
/// running" — three states a bare number cannot express. Without this, a
/// dashboard that receives `eps: null` cannot tell a stopped pipeline from a
/// broken response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum TelemetryState {
    /// A fresh snapshot from a running ingest process.
    Live,
    /// A snapshot exists but is older than the staleness bound, or the
    /// writing process exited without clearing it.
    Stale,
    /// No snapshot has ever been written — ingest has not run.
    Absent,
}

/// Dynamic metrics snapshot polled by the dashboard.
///
/// Every field here is measured. Fields that could not be measured are
/// `null`, never `0` and never a plausible-looking constant — a consumer must
/// be able to tell "no traffic" (`0`) from "no measurement" (`null`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsResponse {
    /// Measured events per second, or `null` when no traffic has been seen.
    pub eps: Option<f64>,
    /// Median per-line parse latency, or `null` when no line has been timed.
    pub latency_p50_micros: Option<f64>,
    /// 99th percentile of the same rolling window.
    pub latency_p99_micros: Option<f64>,
    /// Samples behind the latency window, so the percentiles are auditable.
    pub latency_samples: u64,
    /// Parser signature-cache hit ratio from the real `LruStats`.
    pub lru_hit_rate: Option<f64>,
    /// Lookups behind `lru_hit_rate`.
    pub lru_lookups: Option<u64>,
    /// Messages queued in the bounded ingest queue.
    pub queue_depth: Option<usize>,
    /// Configured bound on `queue_depth`.
    pub queue_capacity: Option<usize>,
    /// Cumulative lines shed by the drop-newest policy.
    pub dropped_count: Option<u64>,
    pub total_ingested: Option<u64>,
    pub total_parsed: Option<u64>,
    pub total_blocks: Option<u64>,
    pub total_anomalies: Option<u64>,

    /// Per-vendor **counts**, from the live parsed-event stream.
    ///
    /// Counts, not percentages: a percentage with no stated base is exactly
    /// the kind of number that misleads. An empty map means no vendor has been
    /// parsed in this ingest process — it is never back-filled with a
    /// fabricated distribution.
    pub vendor_mix: HashMap<String, u64>,
    /// Disposition breakdown over the persisted corpus (see
    /// `disposition_source` for what "persisted" excludes).
    pub disposition_breakdown: HashMap<String, u64>,
    /// How many persisted records the disposition breakdown covers.
    pub disposition_sampled: u64,

    /// Whether the live gauges above are current, stale, or absent.
    pub telemetry_state: TelemetryState,
    /// Age of the underlying snapshot in milliseconds, or `null` when absent.
    pub telemetry_age_ms: Option<u64>,
    /// Where the disposition counts came from, so a reader knows their base.
    pub disposition_source: String,

    /// Pipeline health, derived from real signals.
    ///
    /// `HEALTHY` / `DEGRADED` come from the measured drop counter;
    /// `IDLE` means no live pipeline is publishing; `UNKNOWN` means live
    /// telemetry is unavailable. It is never a constant.
    pub status: String,
}

/// Shared application state across Axum routes.
#[derive(Clone)]
pub struct AppState {
    pub parquet_dir: PathBuf,
    pub ledger_path: PathBuf,
    pub parsers_dir: PathBuf,
    pub eval_report_path: PathBuf,
    pub scratch_dir: PathBuf,
    pub registry: Arc<RwLock<DynamicParserRegistry>>,
    pub alerts: Arc<RwLock<Vec<AlertItem>>>,
    /// Serializes the read-snapshot → publish → rollback sequence in
    /// `POST /onboard`. Two concurrent requests for the same `vendor:model` slug
    /// would otherwise interleave: B snapshots the pair as absent, A publishes
    /// and returns 201, B's YAML write fails, and B's rollback then deletes what
    /// it now sees as "not previously present" — A's published pair, while A's
    /// parser stays registered in memory. A parser that answered 201 is gone
    /// after a restart. One lock around the whole transaction is enough; it is
    /// uncontended in the normal single-request case and never touches the
    /// ingest path.
    pub persist_lock: Arc<tokio::sync::Mutex<()>>,
    pub start_time: Instant,
    /// Live-telemetry sidecar written by the ingest process.
    ///
    /// Public so integration tests can point a state at a temp sidecar and
    /// assert against real snapshots. Production code should prefer
    /// [`AppState::new`], which derives this from the ledger path, or
    /// [`AppState::with_telemetry`] to override it.
    pub telemetry_path: PathBuf,
    /// Staleness bound applied to the snapshot before reporting its gauges.
    pub stale_after_ms: u64,
    /// Whole-response TTL cache. See `serve::metrics_cache` for why the TTL
    /// and the corpus cache are separate layers.
    pub metrics_cache: MetricsCache<MetricsResponse>,
    /// Block-set-keyed cache for the expensive Parquet scan.
    pub corpus_cache: CorpusCache,
}

impl AppState {
    pub fn new(
        parquet_dir: PathBuf,
        ledger_path: PathBuf,
        parsers_dir: PathBuf,
        eval_report_path: PathBuf,
    ) -> Self {
        let scratch_dir = parquet_dir
            .parent()
            .unwrap_or_else(|| Path::new("data"))
            .join("scratch");

        let mut registry = DynamicParserRegistry::new();

        // Scan existing dynamic parsers in parsers_dir
        if parsers_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&parsers_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if p.is_file() {
                        if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                            if ext == "json" {
                                if let Ok(content) = std::fs::read_to_string(&p) {
                                    let _ = registry.load_from_json(&content);
                                }
                            } else if ext == "yaml" || ext == "yml" {
                                if let Ok(content) = std::fs::read_to_string(&p) {
                                    let _ = registry.load_from_yaml(&content);
                                }
                            }
                        }
                    }
                }
            }
        }

        let initial_alerts = Self::compute_initial_alerts(&parquet_dir, &ledger_path);
        let telemetry_path = default_snapshot_path(&ledger_path);

        Self {
            parquet_dir,
            ledger_path,
            parsers_dir,
            eval_report_path,
            scratch_dir,
            registry: Arc::new(RwLock::new(registry)),
            alerts: Arc::new(RwLock::new(initial_alerts)),
            persist_lock: Arc::new(tokio::sync::Mutex::new(())),
            start_time: Instant::now(),
            telemetry_path,
            stale_after_ms: DEFAULT_STALE_AFTER_MS,
            metrics_cache: MetricsCache::new(Duration::from_millis(DEFAULT_METRICS_TTL_MS)),
            corpus_cache: CorpusCache::new(),
        }
    }

    /// Override the sidecar location and staleness bound. Used by tests and by
    /// any deployment that keeps the two planes on separate volumes.
    pub fn with_telemetry(mut self, path: PathBuf, stale_after_ms: u64) -> Self {
        self.telemetry_path = path;
        self.stale_after_ms = stale_after_ms;
        self
    }

    /// Where this state reads live telemetry from.
    pub fn telemetry_path(&self) -> &Path {
        &self.telemetry_path
    }

    /// Override the whole-response TTL. Tests use this to make expiry
    /// deterministic instead of sleeping.
    pub fn with_metrics_ttl(mut self, ttl: Duration) -> Self {
        self.metrics_cache = MetricsCache::new(ttl);
        self
    }

    /// Cached metrics for `GET /metrics`.
    ///
    /// Returns the previous response unchanged while it is inside the TTL,
    /// performing no I/O at all. Past the TTL it recomputes under a mutex, so
    /// concurrent polls produce one recompute rather than N.
    ///
    /// A cached response is returned with the `telemetry_state` and
    /// `telemetry_age_ms` it was computed with. That is deliberate: those
    /// fields describe the freshness of the underlying snapshot as of the
    /// last recompute, and rewriting them on a cache hit would mean reporting
    /// a freshness the cached data does not have.
    pub async fn metrics_cached(&self) -> MetricsResponse {
        if let Some(hit) = self.metrics_cache.get_fresh().await {
            return hit;
        }
        self.metrics_cache
            .refresh(|| self.compute_metrics_with_corpus_cache())
            .await
    }

    /// Scan available blocks for real alerts.
    ///
    /// Every alert here is derived from an actual verification or parse; none
    /// are seeded to make a demo feed look populated. An empty corpus yields
    /// an empty feed, which is the correct answer.
    pub fn compute_initial_alerts(parquet_dir: &Path, ledger_path: &Path) -> Vec<AlertItem> {
        let mut alerts = Vec::new();

        // Audit block 0 if present (intentionally tampered fixture in repo).
        // This is a real `verify_block_with_ledger` call: if the block verifies
        // clean, no alarm is raised, and if it is absent, none is invented.
        let block_0 = parquet_dir.join("block_00000.parquet");
        if block_0.exists() && ledger_path.exists() {
            if let Ok(report) = verify_block_with_ledger(&block_0, ledger_path) {
                if !report.is_valid {
                    let summary = if report.tampered_records.is_empty() {
                        report.summary.clone()
                    } else {
                        let short_hash = report.tampered_records[0]
                            .calculated_raw_hash
                            .get(..16)
                            .unwrap_or(&report.tampered_records[0].calculated_raw_hash);
                        format!(
                            "Corrupted record at leaf {}: calculated SHA-256 {} does not match stored hash.",
                            report.tampered_records[0].leaf_index, short_hash
                        )
                    };
                    alerts.push(AlertItem {
                        id: uuid::Uuid::now_v7().to_string(),
                        alert_type: "tamper_alarm".to_string(),
                        severity: AlertSeverity::Critical,
                        timestamp: chrono::Utc::now().timestamp_millis(),
                        title: "Forensic Tamper Alarm in Block #00000".to_string(),
                        details: summary,
                        block_id: Some(report.block_id),
                        leaf_index: report.tampered_records.first().map(|r| r.leaf_index),
                    });
                }
            }
        }

        // Drain drift and rare-cluster surges are published by the running
        // ingest process through the telemetry sidecar while traffic flows.
        // They are deliberately NOT synthesized here: before this change two
        // fabricated alerts ("Parser Drift", "Traffic Volume Spike") were
        // appended unconditionally, so the feed claimed parser drift and a
        // volume spike on a system that had never seen traffic.
        alerts
    }

    /// Asynchronously re-seeds alerts from the current blocks.
    pub async fn seed_initial_alerts(&self) {
        let alerts = Self::compute_initial_alerts(&self.parquet_dir, &self.ledger_path);
        let mut lock = self.alerts.write().await;
        *lock = alerts;
    }

    /// Read the live telemetry sidecar, if the ingest process wrote one.
    ///
    /// A corrupt sidecar is reported as absent-with-warning rather than
    /// propagated as an error: a broken telemetry file must not take down
    /// `/metrics`, but it must also not be silently treated as healthy.
    fn read_live_telemetry(&self) -> Option<IngestSnapshot> {
        match read_snapshot(&self.telemetry_path) {
            Ok(snap) => snap,
            Err(e) => {
                tracing::warn!("live telemetry unreadable: {e}");
                None
            }
        }
    }

    /// Aggregated metrics, all measured.
    ///
    /// Two sources, kept deliberately separate:
    ///
    /// * **Live gauges** (eps, latency, LRU, queue) come from the ingest
    ///   sidecar, because that is the only place they exist. When the sidecar
    ///   is absent or stale they report `null`.
    /// * **Persisted corpus counts** (blocks, dispositions) come from the
    ///   ledger and Parquet, which outlive any single process.
    pub async fn compute_metrics(&self) -> MetricsResponse {
        let (total_blocks, ledger_ingested) = self.read_ledger_totals();
        let (disposition_breakdown, disposition_sampled) = self.read_dispositions();
        let live = self.read_live_telemetry();
        self.assemble_metrics(
            total_blocks,
            ledger_ingested,
            disposition_breakdown,
            disposition_sampled,
            live,
        )
    }

    /// `compute_metrics` with the expensive Parquet scan served from the
    /// block-set cache.
    ///
    /// The ledger fingerprint is read once per recompute — one `stat`, not a
    /// parse — and only a changed block set re-runs the scan. This is what
    /// keeps the TTL from degrading into "re-decode 5,000 Parquet rows every
    /// second", which is what the TTL would otherwise mean.
    async fn compute_metrics_with_corpus_cache(&self) -> MetricsResponse {
        let fingerprint = fingerprint_ledger(&self.ledger_path);
        let cached = self.corpus_cache.get(fingerprint).await;

        // All file I/O for a recompute happens on `spawn_blocking`, never on a
        // runtime worker. This is real blocking work — Parquet decode plus a
        // full ledger parse — and left inline it would stall the worker for
        // the whole scan while every other `/metrics` poll sat queued behind
        // the recompute mutex.
        //
        // The sidecar is re-read inline, on every recompute, even when the
        // corpus cache hits: the live gauges have to keep moving, and they come
        // from the sidecar, not from the block set. It is deliberately *not*
        // routed through `spawn_blocking` — it is a single ~1 KB file read,
        // tens of microseconds, and paying a thread-pool handoff for it every
        // cache miss measurably slowed the cached path (0.13 ms → 0.60 ms
        // median) to avoid stalling a worker for a duration that is not a
        // stall. Only the multi-millisecond scan goes off-worker.
        // A hit does no blocking work and spawns no task — the whole point of
        // the corpus cache is that the steady state costs nothing. The scan
        // only reaches `spawn_blocking` when it actually has to run.
        let aggregates = match cached {
            Some(hit) => hit,
            None => {
                let scan = self.clone();
                // Only a *successful* scan is cached. Caching the failure
                // fallback would pin empty aggregates under the current
                // fingerprint until the ledger next changes, so a transient
                // panic would blank `total_blocks` and dispositions
                // indefinitely on a quiet corpus. A failed scan is reported
                // once and then retried on the next recompute.
                let computed = tokio::task::spawn_blocking(move || {
                    let (breakdown, sampled) = scan.read_dispositions();
                    CorpusAggregates {
                        disposition_breakdown: breakdown,
                        disposition_sampled: sampled,
                        ledger_totals: scan.read_ledger_totals(),
                    }
                })
                .await;
                match computed {
                    Ok(fresh) => {
                        self.corpus_cache.put(fingerprint, fresh.clone()).await;
                        fresh
                    }
                    Err(e) => {
                        // Do not cache this. Empty aggregates are reported as
                        // "nothing measured" rather than as a fabricated
                        // zero, and the next recompute tries again.
                        tracing::error!("corpus scan task failed: {e}");
                        CorpusAggregates::default()
                    }
                }
            }
        };
        let (total_blocks, ledger_ingested) = aggregates.ledger_totals;
        let live = self.read_live_telemetry();
        self.assemble_metrics(
            total_blocks,
            ledger_ingested,
            aggregates.disposition_breakdown,
            aggregates.disposition_sampled,
            live,
        )
    }

    /// Build the response from already-gathered inputs.
    #[allow(clippy::too_many_arguments)]
    fn assemble_metrics(
        &self,
        total_blocks: u64,
        ledger_ingested: u64,
        disposition_breakdown: HashMap<String, u64>,
        disposition_sampled: u64,
        live: Option<IngestSnapshot>,
    ) -> MetricsResponse {
        let (telemetry_state, telemetry_age_ms, gauge) = match &live {
            None => (TelemetryState::Absent, None, IngestSnapshot::default()),
            Some(snap) => {
                // `running: false` means the writer exited cleanly. Its live
                // gauges describe a pipeline that no longer exists, so they
                // are cleared here for the same reason the stale path clears
                // them. The age is still reported — it is a real wall-clock
                // distance, and a reader may want to know how long ago the
                // writer stopped. Reporting `u64::MAX` instead would be a
                // number that means nothing.
                if !snap.running {
                    let age = self
                        .wall_clock_age_ms(snap.unix_ms)
                        .map(|a| a.max(0) as u64);
                    (TelemetryState::Stale, age, snap.without_live_gauges())
                } else {
                    // Age is computed against wall-clock proximity because the
                    // two processes do not share a monotonic epoch. Comparing
                    // the snapshot's own age field is impossible across
                    // processes, so the conservative bound is used: a snapshot
                    // is current only while its writer says it is still
                    // running and it was written recently in wall-clock terms.
                    let age = self.wall_clock_age_ms(snap.unix_ms);
                    let fresh = age
                        .map(|a| a <= self.stale_after_ms as i64)
                        .unwrap_or(false);
                    let state = if fresh {
                        TelemetryState::Live
                    } else {
                        TelemetryState::Stale
                    };
                    // A stale reading is not a live one. Clear the gauges
                    // rather than serving numbers that quietly stopped
                    // moving; the cumulative fields survive because they are
                    // still true, just not current.
                    let reported = if fresh {
                        snap.clone()
                    } else {
                        snap.without_live_gauges()
                    };
                    (state, age.map(|a| a.max(0) as u64), reported)
                }
            }
        };

        let vendor_mix: HashMap<String, u64> = gauge
            .vendor_counts
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();

        // Prefer the live counter. The `> 0` filter applies ONLY to the ledger
        // fallback, never to the live measurement: a snapshot reporting
        // `total_ingested: 0` is a real observation of a running pipeline that
        // has ingested nothing yet, and collapsing it to `null` would break
        // the documented contract that `0` and `null` mean different things.
        let total_ingested = match gauge.total_ingested {
            Some(measured) => Some(measured),
            None if ledger_ingested > 0 => Some(ledger_ingested),
            None => None,
        };
        // Same rule for block count: the ledger is the durable authority and
        // outlives the ingest process, so it wins whenever it has entries. A
        // cleared (stale) snapshot retains these cumulative fields, so the
        // fallback keeps working after ingest stops.
        let total_blocks = if total_blocks > 0 {
            Some(total_blocks)
        } else {
            gauge.total_blocks
        };

        let status = match telemetry_state {
            TelemetryState::Live => match gauge.dropped_count {
                Some(0) => "HEALTHY",
                Some(_) => "DEGRADED",
                None => "UNKNOWN",
            },
            TelemetryState::Stale => "IDLE",
            TelemetryState::Absent => "UNKNOWN",
        }
        .to_string();

        MetricsResponse {
            eps: gauge.eps,
            latency_p50_micros: gauge.latency_p50_micros,
            latency_p99_micros: gauge.latency_p99_micros,
            latency_samples: gauge.latency_samples,
            lru_hit_rate: gauge.lru_hit_rate,
            lru_lookups: gauge.lru_lookups,
            queue_depth: gauge.queue_depth,
            queue_capacity: gauge.queue_capacity,
            dropped_count: gauge.dropped_count,
            total_ingested,
            total_parsed: gauge.total_parsed,
            total_blocks,
            total_anomalies: gauge.total_anomalies,
            vendor_mix,
            disposition_breakdown,
            disposition_sampled,
            telemetry_state,
            telemetry_age_ms,
            disposition_source: "persisted_parquet_sample".to_string(),
            status,
        }
    }

    /// Total blocks and total leaves from the ledger.
    fn read_ledger_totals(&self) -> (u64, u64) {
        if !self.ledger_path.exists() {
            return (0, 0);
        }
        match BatchAccumulator::load_ledger_entries(&self.ledger_path) {
            Ok(entries) => {
                let blocks = entries.len() as u64;
                let leaves = entries.iter().map(|e| e.leaf_count as u64).sum();
                (blocks, leaves)
            }
            // A malformed ledger yields no totals. Reporting zero here would
            // read as "an empty corpus" rather than "could not be read".
            Err(e) => {
                tracing::warn!("ledger unreadable: {e}");
                (0, 0)
            }
        }
    }

    /// Disposition counts over a bounded sample of persisted records.
    ///
    /// Bounded because this runs in the request path; the sample size is
    /// reported alongside the counts so a reader knows the base. Only
    /// dispositions actually present are included — an empty corpus produces
    /// an empty map, never a zeroed template of `Allowed`/`Blocked`/`Dropped`.
    fn read_dispositions(&self) -> (HashMap<String, u64>, u64) {
        const MAX_SAMPLE: u64 = 5_000;
        let mut counts: HashMap<String, u64> = HashMap::new();
        let mut sampled = 0u64;

        if !self.parquet_dir.exists() {
            return (counts, sampled);
        }
        let Ok(entries) = std::fs::read_dir(&self.parquet_dir) else {
            return (counts, sampled);
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) != Some("parquet") {
                continue;
            }
            let Ok(records) = read_parquet_file(&p) else {
                continue;
            };
            for r in records {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&r.ocsf_json) {
                    if let Some(disp) = val.get("disposition").and_then(|v| v.as_str()) {
                        *counts.entry(disp.to_string()).or_insert(0) += 1;
                    }
                }
                sampled += 1;
                if sampled >= MAX_SAMPLE {
                    return (counts, sampled);
                }
            }
        }
        (counts, sampled)
    }

    /// Milliseconds elapsed since `unix_ms`, or `None` if it is in the future.
    ///
    /// The only clock the two processes genuinely share is wall time, so this
    /// is what staleness has to be judged on. A snapshot stamped in the future
    /// means the writer's clock is ahead of ours; that is a clock skew, not a
    /// reason to report a reading as infinitely old, so it reads as
    /// not-fresh without inventing a huge age.
    fn wall_clock_age_ms(&self, unix_ms: i64) -> Option<i64> {
        let now = chrono::Utc::now().timestamp_millis();
        let age = now - unix_ms;
        if age < 0 {
            None
        } else {
            Some(age)
        }
    }
}
