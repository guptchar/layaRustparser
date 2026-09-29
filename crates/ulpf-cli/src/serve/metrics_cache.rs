//! Caching for `GET /metrics`.
//!
//! # Why this exists
//!
//! [`super::state::AppState::compute_metrics`] does three jobs of very
//! different cost: read a small telemetry sidecar, parse the **entire**
//! append-only ledger, and decode Parquet blocks until it has 5,000 records.
//! The dashboard polls `/metrics` every second. Doing that work per request
//! is what issue #56 was filed for.
//!
//! # Two layers, two invalidation signals
//!
//! **Whole-response TTL.** Inside the TTL the handler returns the previously
//! computed response and performs no I/O at all — not even a `stat`. This is
//! the literal reading of the acceptance criterion, and deliberately so: if
//! freshness were checked by touching the filesystem, "no I/O" would be true
//! only in a technical sense while still costing a syscall per poll.
//!
//! **Parquet scan, keyed on the ledger.** When the TTL does expire, the
//! expensive Parquet walk does not re-run just because time passed. It re-runs
//! only when the block set actually changed, fingerprinted as the ledger's
//! `(mtime, len)`. Every anchored block appends a ledger line, so that pair is
//! precisely the "new blocks exist" signal — and reading it costs one `stat`
//! instead of a full parse plus a Parquet walk.
//!
//! # Why the sidecar is *not* part of the fingerprint
//!
//! A running ingest process rewrites the telemetry sidecar every second. If
//! sidecar freshness invalidated the cache, the cache would miss on every poll
//! — exactly the behaviour it exists to prevent. The TTL already bounds how
//! stale the live gauges can be, which is the property a polling client
//! actually needs, so the sidecar is re-read on TTL expiry and never before.
//!
//! # Concurrency
//!
//! Recompute happens under a single mutex. With only a `RwLock`, every
//! concurrent poll past the TTL would independently enter the recompute and
//! stampede the Parquet scan together — the same load the cache exists to
//! remove. The mutex makes it one recompute and N-1 cache hits.
//!
//! **The guarantee depends on the TTL outlasting the recompute.** A waiter
//! queued on the mutex re-checks freshness once it acquires the lock; if the
//! entry has expired again by then it legitimately recomputes. So if the TTL
//! is shorter than one recompute plus scheduling jitter, a burst produces
//! several recomputes rather than one. That is correct behaviour, not a
//! stampede, and it is why the default TTL is a second rather than
//! microseconds.

use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, RwLock};

/// Default whole-response TTL, in milliseconds.
///
/// One second matches the dashboard's poll interval, so in the steady state a
/// poll almost always lands just after a refresh rather than just before one.
/// The cost is explicit and accepted: a block anchored mid-interval is not
/// visible until the next refresh. For a live dashboard that is a one-second
/// lag, traded against re-decoding up to 5,000 Parquet rows on every poll.
pub const DEFAULT_METRICS_TTL_MS: u64 = 1_000;

/// Cheap change detector for the persisted block set.
///
/// `(mtime, len)` of the ledger. Every anchored block appends a line, so a
/// changed pair means the block set moved. A missing ledger maps to `None`,
/// which is stable — an absent ledger stays absent until one appears.
type LedgerFingerprint = Option<(std::time::SystemTime, u64)>;

pub fn fingerprint_ledger(path: &Path) -> LedgerFingerprint {
    match std::fs::metadata(path) {
        Ok(meta) => {
            let mtime = meta.modified().ok();
            // A filesystem without mtime support still gives us a length, so
            // fall back to `(None, len)` rather than giving up entirely: a
            // ledger that only grows is still detected by its length.
            Some((mtime.unwrap_or(std::time::UNIX_EPOCH), meta.len()))
        }
        Err(_) => None,
    }
}

/// The expensive, block-set-dependent half of the metrics response.
///
/// The ledger totals live here too, not just the Parquet scan. The ledger is
/// append-only and grows without bound, so re-parsing it per recompute would
/// reintroduce exactly the cost this cache exists to remove — and it is the
/// cost that gets worse over time, since a long-running deployment accumulates
/// more ledger lines.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CorpusAggregates {
    pub disposition_breakdown: std::collections::HashMap<String, u64>,
    pub disposition_sampled: u64,
    /// `(total_blocks, total_ingested)` as of the fingerprint these were
    /// computed from.
    pub ledger_totals: (u64, u64),
}

/// Cache of the last computed metrics response plus its derived aggregates.
///
/// `AppState` is cloned by axum for every request, so the cache is `Arc`-
/// wrapped: a derived `Clone` hands out another handle to the *same* cache.
/// Copying it would give each request its own cache and the hit rate would be
/// zero, which is a failure mode that looks exactly like the cache not working.
#[derive(Debug)]
pub struct MetricsCache<T> {
    ttl: Duration,
    inner: Arc<RwLock<Option<CachedEntry<T>>>>,
    /// Serialises recompute. See the module docs on stampeding.
    recompute_lock: Arc<Mutex<()>>,
    /// Count of actual recomputes, for tests and diagnostics.
    recomputes: Arc<AtomicU64>,
}

impl<T> Clone for MetricsCache<T> {
    fn clone(&self) -> Self {
        Self {
            ttl: self.ttl,
            inner: self.inner.clone(),
            recompute_lock: self.recompute_lock.clone(),
            recomputes: self.recomputes.clone(),
        }
    }
}

#[derive(Debug, Clone)]
struct CachedEntry<T> {
    value: T,
    computed_at: Instant,
}

impl<T> MetricsCache<T> {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: Arc::new(RwLock::new(None)),
            recompute_lock: Arc::new(Mutex::new(())),
            recomputes: Arc::new(AtomicU64::new(0)),
        }
    }

    /// How many times a recompute actually ran. Tests assert on this to prove
    /// a poll inside the TTL did no work.
    pub fn recompute_count(&self) -> u64 {
        self.recomputes.load(Ordering::Relaxed)
    }

    /// The cached value if it is still inside the TTL.
    ///
    /// Takes no lock and performs no I/O beyond an `Instant` read.
    pub async fn get_fresh(&self) -> Option<T>
    where
        T: Clone,
    {
        let guard = self.inner.read().await;
        match guard.as_ref() {
            Some(entry) if entry.computed_at.elapsed() <= self.ttl => Some(entry.value.clone()),
            _ => None,
        }
    }

    /// Force a recompute, serialised against other recomputes.
    ///
    /// Double-checked inside the mutex: a caller that waited for another
    /// caller's recompute reuses its result instead of immediately starting a
    /// second one.
    pub async fn refresh<F, Fut>(&self, compute: F) -> T
    where
        T: Clone,
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = T>,
    {
        let _guard = self.recompute_lock.lock().await;
        if let Some(entry) = self.inner.read().await.as_ref() {
            if entry.computed_at.elapsed() <= self.ttl {
                return entry.value.clone();
            }
        }
        let value = compute().await;
        self.recomputes.fetch_add(1, Ordering::Relaxed);
        *self.inner.write().await = Some(CachedEntry {
            value: value.clone(),
            computed_at: Instant::now(),
        });
        value
    }

    /// Drop any cached value, forcing the next read to recompute.
    pub async fn invalidate(&self) {
        *self.inner.write().await = None;
    }
}

/// Cache for the block-set-dependent aggregates, keyed on the ledger.
///
/// Separate from the response TTL because its invalidation signal is
/// different: these numbers only move when blocks are anchored, which may be
/// every second during heavy ingest or once an hour otherwise. Re-decoding
/// 5,000 Parquet rows on the TTL alone would make the TTL pointless.
#[derive(Debug)]
pub struct CorpusCache {
    inner: Arc<RwLock<Option<(LedgerFingerprint, CorpusAggregates)>>>,
}

impl Clone for CorpusCache {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl CorpusCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(None)),
        }
    }

    /// Return the cached aggregates if the block set has not changed.
    pub async fn get(&self, fingerprint: LedgerFingerprint) -> Option<CorpusAggregates> {
        let guard = self.inner.read().await;
        match guard.as_ref() {
            // Compare only the fingerprint. Holding a guard across the
            // (expensive) recompute would serialize every request behind one
            // another; the write lock is taken only to publish.
            Some((cached_fp, aggregates)) if *cached_fp == fingerprint => Some(aggregates.clone()),
            _ => None,
        }
    }

    /// Store aggregates for the fingerprint they were computed from.
    pub async fn put(&self, fingerprint: LedgerFingerprint, aggregates: CorpusAggregates) {
        *self.inner.write().await = Some((fingerprint, aggregates));
    }
}

impl Default for CorpusCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Shared handle, cheap to clone into request handlers.
pub type SharedMetricsCache<T> = Arc<MetricsCache<T>>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    #[tokio::test]
    async fn test_poll_inside_ttl_does_no_recompute() {
        let cache: MetricsCache<u32> = MetricsCache::new(Duration::from_secs(60));
        let calls = Arc::new(AtomicU32::new(0));

        let first = {
            let calls = calls.clone();
            cache
                .refresh(|| async {
                    calls.fetch_add(1, Ordering::Relaxed);
                    42
                })
                .await
        };
        assert_eq!(first, 42);
        assert_eq!(cache.recompute_count(), 1);

        // Many polls inside the TTL. Each must be served from cache: no
        // recompute, and no I/O of any kind.
        for _ in 0..50 {
            assert_eq!(cache.get_fresh().await, Some(42));
        }
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "a poll inside the TTL must not re-run the computation"
        );
        assert_eq!(cache.recompute_count(), 1);
    }

    #[tokio::test]
    async fn test_expired_entry_is_not_returned_as_fresh() {
        let cache: MetricsCache<u32> = MetricsCache::new(Duration::from_millis(1));
        cache.refresh(|| async { 7 }).await;
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert_eq!(
            cache.get_fresh().await,
            None,
            "an expired entry must not be served as fresh"
        );
    }

    /// Concurrent polls past the TTL must produce exactly one recompute.
    /// Without the recompute mutex every one of them would enter the
    /// computation together — the stampede this cache exists to prevent.
    #[tokio::test]
    async fn test_concurrent_polls_recompute_once() {
        let cache: Arc<MetricsCache<u32>> = Arc::new(MetricsCache::new(Duration::from_millis(20)));
        let calls = Arc::new(AtomicU32::new(0));
        cache.refresh(|| async { 1 }).await;
        // Let the entry expire so every task below needs a recompute.
        tokio::time::sleep(Duration::from_millis(40)).await;

        let mut handles = Vec::new();
        for _ in 0..16 {
            let cache = cache.clone();
            let calls = calls.clone();
            handles.push(tokio::spawn(async move {
                cache
                    .refresh(|| async {
                        calls.fetch_add(1, Ordering::Relaxed);
                        // A slow computation widens the window in which a
                        // second caller could slip past the double-check.
                        tokio::time::sleep(Duration::from_millis(30)).await;
                        9
                    })
                    .await
            }));
        }
        for h in handles {
            assert_eq!(h.await.expect("task must not panic"), 9);
        }
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "16 concurrent polls past the TTL must cause exactly one recompute, not 16"
        );
    }

    #[tokio::test]
    async fn test_invalidate_forces_recompute() {
        let cache: MetricsCache<u32> = MetricsCache::new(Duration::from_secs(60));
        cache.refresh(|| async { 1 }).await;
        assert_eq!(cache.get_fresh().await, Some(1));
        cache.invalidate().await;
        assert_eq!(cache.get_fresh().await, None);
        assert_eq!(cache.refresh(|| async { 2 }).await, 2);
        assert_eq!(cache.recompute_count(), 2);
    }

    /// The corpus cache must survive an unchanged block set and invalidate the
    /// moment the fingerprint moves.
    #[tokio::test]
    async fn test_corpus_cache_keys_on_fingerprint() {
        let cache = CorpusCache::new();
        let fp_a = Some((std::time::UNIX_EPOCH, 100u64));
        let fp_b = Some((std::time::UNIX_EPOCH, 200u64));

        assert_eq!(cache.get(fp_a).await, None, "cold cache misses");

        let aggregates = CorpusAggregates {
            disposition_breakdown: [("Allowed".to_string(), 10u64)].into_iter().collect(),
            disposition_sampled: 10,
            ledger_totals: (2, 500),
        };
        cache.put(fp_a, aggregates.clone()).await;

        assert_eq!(
            cache.get(fp_a).await,
            Some(aggregates.clone()),
            "an unchanged block set must hit"
        );
        assert_eq!(
            cache.get(fp_b).await,
            None,
            "a grown ledger must invalidate the cached scan"
        );
    }

    /// A missing ledger fingerprints as `None` and must stay stable, so an
    /// empty corpus does not invalidate on every request.
    #[tokio::test]
    async fn test_missing_ledger_fingerprint_is_stable() {
        let cache = CorpusCache::new();
        let aggregates = CorpusAggregates::default();
        cache.put(None, aggregates.clone()).await;
        assert_eq!(cache.get(None).await, Some(aggregates));
    }

    /// A real file's fingerprint must change when it grows — this is the
    /// invalidation signal the whole design rests on.
    #[test]
    fn test_fingerprint_changes_when_ledger_grows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.jsonl");
        std::fs::write(&path, b"one\n").unwrap();
        let first = fingerprint_ledger(&path);
        assert!(first.is_some(), "an existing ledger must fingerprint");

        std::fs::write(&path, b"one\ntwo\nthree\n").unwrap();
        let second = fingerprint_ledger(&path);
        assert_ne!(
            first, second,
            "an appended block must change the fingerprint so the scan re-runs"
        );
    }

    #[test]
    fn test_absent_ledger_fingerprints_as_none() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(fingerprint_ledger(&dir.path().join("nope.jsonl")), None);
    }
}
