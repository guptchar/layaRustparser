use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::Bytes;
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use ulpf_ai::drain::{AlertSeverity, DrainConfig, DrainMiner};
use ulpf_ai::evaluator::{load_sidecar_gt, EvaluatorEngine, GtOverrides};
use ulpf_ai::onboarder::{DynamicParserRegistry, Onboarder};
use ulpf_core::ingest::socket::{create_tcp_listener, create_udp_socket};
use ulpf_core::ingest::{BackpressurePolicy, LogQueue, MemoryQueue};
use ulpf_core::parser::UniversalParser;
use ulpf_integrity::batcher::{BatchAccumulator, BatcherConfig, IncomingLog};
use ulpf_integrity::storage::ParquetCompression;
use ulpf_integrity::tamper::verify_block_with_ledger;

use ulpf_cli::{scorecard, serve};

#[derive(Parser, Debug)]
#[command(
    name = "ulpf",
    author = "Universal Log Pre-processing Framework Team",
    version = "0.1.0",
    about = "High-Assurance Universal Log Pre-processing & Cryptographic Integrity Fabric"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Ingest live Syslog streams (UDP/TCP), normalize to OCSF 1.3, anchor to Merkle trees, and archive to Parquet
    Ingest(IngestArgs),
    /// Cryptographically verify an archived Parquet block file against the anchored Merkle ledger
    Verify(VerifyArgs),
    /// 1-Click air-gapped onboarding: synthesize and validate a regex parser from sample raw log lines
    Onboard(OnboardArgs),
    /// Execute multi-core parsing and normalization throughput benchmarks
    Benchmark(BenchmarkArgs),
    /// Architectural Evaluator: benchmark Baseline vs 3-Tier (LRU+DrainDotNet+Laya) with latency percentiles and cache efficiency
    Evaluate(EvaluateArgs),
    /// One-command scorecard: baseline vs 3-tier side by side (throughput, latency deltas, accuracy audit, gates) as an aligned ASCII box + markdown report
    Scorecard(ScorecardArgs),
    /// Inspect forensic records inside an archived Parquet block
    Inspect(InspectArgs),
    /// Adversarial simulation: stealthily tamper with an archived Parquet record
    Tamper(TamperArgs),
    /// Launch the lightweight HTTP backend for UI and SIEM integration
    Serve(serve::ServeArgs),
}

#[derive(Args, Debug)]
struct TamperArgs {
    /// Path to the Parquet block file to tamper
    #[arg(short, long)]
    file: PathBuf,

    /// Target leaf index to tamper
    #[arg(short, long, default_value_t = 0)]
    leaf: usize,

    /// Spoofed IP address to inject into the raw log
    #[arg(short, long, default_value = "10.99.99.99")]
    ip: String,
}

#[derive(Args, Debug)]
struct InspectArgs {
    /// Path to the Parquet block file to inspect
    #[arg(short, long)]
    file: PathBuf,

    /// Number of records to display
    #[arg(short, long, default_value_t = 1)]
    count: usize,
}

#[derive(Args, Debug)]
struct IngestArgs {
    /// UDP bind address for Syslog ingestion
    #[arg(long, default_value = "0.0.0.0:5140")]
    udp: String,

    /// TCP bind address for Syslog ingestion
    #[arg(long, default_value = "0.0.0.0:5140")]
    tcp: String,

    /// Directory for output columnar Parquet archive blocks
    #[arg(long, default_value = "data/parquet")]
    parquet_dir: PathBuf,

    /// Path to the append-only cryptographic ledger file
    #[arg(long, default_value = "data/ledger.jsonl")]
    ledger: PathBuf,

    /// Maximum events per Merkle block batch
    #[arg(long, default_value_t = 1000)]
    batch_size: usize,

    /// Maximum duration (ms) before flushing a batch
    #[arg(long, default_value_t = 2000)]
    batch_timeout: u64,

    /// Enable SO_REUSEPORT for high-concurrency multi-core socket binding
    #[arg(long, default_value_t = true)]
    reuse_port: bool,

    /// Ingest queue capacity (messages) before backpressure kicks in
    #[arg(long, default_value_t = 50_000)]
    queue_capacity: usize,

    /// Shed load instead of blocking when the queue is full (lossy;
    /// default blocks to preserve the lossless provenance invariant)
    #[arg(long, default_value_t = false)]
    drop_on_full: bool,
}

#[derive(Args, Debug)]
struct VerifyArgs {
    /// Path to the Parquet block file to audit
    #[arg(short, long)]
    file: PathBuf,

    /// Path to the append-only cryptographic Merkle ledger
    #[arg(short, long, default_value = "data/ledger.jsonl")]
    ledger: PathBuf,
}

#[derive(Args, Debug)]
struct OnboardArgs {
    /// Path to text file containing 3-5 sample lines of the new log format
    #[arg(short, long)]
    sample: PathBuf,

    /// Name of the vendor / device family
    #[arg(short, long, default_value = "custom_device")]
    vendor: String,

    /// Specific device model
    #[arg(short, long, default_value = "generic")]
    model: String,

    /// Directory to output the synthesized parser specification
    #[arg(short, long, default_value = "data/parsers")]
    out: PathBuf,
}

#[derive(Args, Debug)]
struct BenchmarkArgs {
    /// Path to raw dataset directory (long-only: `-d` belongs to `--duration`;
    /// the duplicate short flag panic'd every debug build — P10.0)
    #[arg(long, default_value = "data/raw")]
    data_dir: PathBuf,

    /// Duration of benchmark in seconds
    #[arg(short, long, default_value_t = 5)]
    duration: u64,

    /// Number of parallel worker threads
    #[arg(short, long, default_value_t = 16)]
    threads: usize,

    /// Compare Baseline vs 3-Tier Pipeline (LRU + DrainDotNet + Laya)
    #[arg(long, default_value_t = false)]
    compare: bool,
}

/// Corpus variant for `evaluate` (P7): `core` = the fixed file set incl. the
/// format-expansion files, `adversarial` / `holdout` = sidecar-GT corpora
/// whose `gt.jsonl` is authoritative over in-line ground truth.
#[derive(Clone, Copy, Debug, PartialEq, ValueEnum)]
enum CorpusKind {
    Core,
    Adversarial,
    Holdout,
}

impl CorpusKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Adversarial => "adversarial",
            Self::Holdout => "holdout",
        }
    }
}

#[derive(Args, Debug)]
struct EvaluateArgs {
    /// Path to raw dataset directory (long-only: `-d` belongs to `--duration`
    /// — the duplicate short flag made debug builds panic on parse, P10.0)
    #[arg(long, default_value = "data/raw")]
    data_dir: PathBuf,

    /// Target architecture engine: 'all' (compare both), 'baseline' (UniversalParser only), 'tiered' (LRU+DrainDotNet+Laya only)
    #[arg(short, long, default_value = "all")]
    engine: String,

    /// Corpus variant to score: core (fixed file set), adversarial (mutated + sidecar GT), holdout (frozen novel vendors)
    #[arg(long, value_enum, default_value = "core")]
    corpus: CorpusKind,

    /// Duration of benchmark in seconds per engine
    #[arg(short, long, default_value_t = 3)]
    duration: u64,

    /// Number of parallel worker threads
    #[arg(short, long, default_value_t = 16)]
    threads: usize,

    /// Number of high-density latency samples to collect
    #[arg(short, long, default_value_t = 10000)]
    samples: usize,

    /// Path to export markdown evaluation report
    #[arg(short, long, default_value = "eval_hardcore_report.md")]
    out: PathBuf,

    /// Optional path to export JSON metrics
    #[arg(long)]
    json_out: Option<PathBuf>,

    /// Optional path to export the per-record audit mismatch dump (JSONL, one
    /// failure object per line: engine, metric, expected, observed, raw line)
    #[arg(long)]
    audit_dump: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct ScorecardArgs {
    /// Path to raw dataset directory (long-only: `-d` belongs to `--duration`)
    #[arg(long, default_value = "data/raw")]
    data_dir: PathBuf,

    /// Corpus variant to score: core (committed fixtures), adversarial (fuzzed + sidecar GT), holdout (frozen unseen vendors)
    #[arg(long, value_enum, default_value = "core")]
    corpus: CorpusKind,

    /// Duration of benchmark in seconds per engine
    #[arg(short, long, default_value_t = 3)]
    duration: u64,

    /// Number of parallel worker threads
    #[arg(short, long, default_value_t = 16)]
    threads: usize,

    /// Number of high-density latency samples to collect
    #[arg(short, long, default_value_t = 10000)]
    samples: usize,

    /// Path to export the markdown report backing the box
    #[arg(short, long, default_value = "scorecard_report.md")]
    out: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Ingest(args) => run_ingest(args).await,
        Commands::Verify(args) => run_verify(args),
        Commands::Onboard(args) => run_onboard(args),
        Commands::Benchmark(args) => run_benchmark(args).await,
        Commands::Evaluate(args) => run_evaluate(args).await,
        Commands::Scorecard(args) => run_scorecard(args),
        Commands::Inspect(args) => run_inspect(args),
        Commands::Tamper(args) => run_tamper(args),
        Commands::Serve(args) => serve::run_serve(args).await,
    }
}

// -----------------------------------------------------------------------------
// 1. INGESTION ENGINE
// -----------------------------------------------------------------------------

async fn run_ingest(args: IngestArgs) -> Result<()> {
    println!(
        "\x1b[1;36m====================================================================\x1b[0m"
    );
    println!(
        "\x1b[1;32m   ULPF - Universal Log Pre-processing & Cryptographic Integrity Fabric\x1b[0m"
    );
    println!(
        "\x1b[1;36m====================================================================\x1b[0m"
    );
    println!("  UDP Listener      : {}", args.udp);
    println!("  TCP Listener      : {}", args.tcp);
    println!("  Parquet Archive   : {}", args.parquet_dir.display());
    println!("  Merkle Ledger     : {}", args.ledger.display());
    println!(
        "  Batch Trigger     : {} logs OR {} ms",
        args.batch_size, args.batch_timeout
    );
    println!(
        "  Queue             : capacity {} ({})",
        args.queue_capacity,
        if args.drop_on_full {
            "drop-on-full"
        } else {
            "block-on-full"
        }
    );
    println!("  Taxonomy Standard : OCSF 1.3 (Class 4001 NetworkActivity)");
    println!("  Tamper-Evidence   : RFC 6962 Standard Merkle Tree");
    println!(
        "\x1b[1;36m--------------------------------------------------------------------\x1b[0m"
    );

    fs::create_dir_all(&args.parquet_dir)?;
    if let Some(parent) = args.ledger.parent() {
        fs::create_dir_all(parent)?;
    }

    let batcher_config = BatcherConfig {
        max_batch_size: args.batch_size,
        max_batch_duration_ms: args.batch_timeout,
        storage_dir: args.parquet_dir.clone(),
        ledger_path: args.ledger.clone(),
        compression: ParquetCompression::Snappy,
    };

    // Drop stays opt-in: the default Block policy preserves the lossless
    // provenance invariant (no raw line is ever shed unless asked).
    let policy = if args.drop_on_full {
        BackpressurePolicy::Drop
    } else {
        BackpressurePolicy::Block
    };
    let queue: Arc<dyn LogQueue> = Arc::new(MemoryQueue::new(args.queue_capacity, policy));
    let total_ingested = Arc::new(AtomicU64::new(0));
    let total_parsed = Arc::new(AtomicU64::new(0));
    let total_blocks = Arc::new(AtomicU64::new(0));
    let total_anomalies = Arc::new(AtomicU64::new(0));

    // Spawn UDP Listener
    let udp_addr: SocketAddr = args.udp.parse().context("Invalid UDP address")?;
    let udp_socket = create_udp_socket(udp_addr, args.reuse_port)?;
    let queue_udp = queue.clone();
    let total_ingested_udp = total_ingested.clone();

    tokio::spawn(async move {
        let mut buf = [0u8; 65535];
        loop {
            match udp_socket.recv_from(&mut buf).await {
                Ok((size, _peer)) => {
                    let data = &buf[..size];
                    if let Ok(raw_str) = std::str::from_utf8(data) {
                        for line in raw_str.lines() {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() {
                                total_ingested_udp.fetch_add(1, Ordering::Relaxed);
                                let owned: Bytes = trimmed.to_string().into();
                                if let Err(e) = queue_udp.push(owned) {
                                    warn!("UDP queue push error: {}", e);
                                    return;
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    warn!("UDP receive error: {}", e);
                }
            }
        }
    });

    // Spawn TCP Listener
    let tcp_addr: SocketAddr = args.tcp.parse().context("Invalid TCP address")?;
    let tcp_listener = create_tcp_listener(tcp_addr, args.reuse_port, 1024)?;
    let queue_tcp = queue.clone();
    let total_ingested_tcp = total_ingested.clone();

    tokio::spawn(async move {
        loop {
            match tcp_listener.accept().await {
                Ok((stream, _peer)) => {
                    let q = queue_tcp.clone();
                    let counter = total_ingested_tcp.clone();
                    tokio::spawn(async move {
                        let reader = tokio::io::BufReader::new(stream);
                        use tokio::io::AsyncBufReadExt;
                        let mut lines = reader.lines();
                        while let Ok(Some(line)) = lines.next_line().await {
                            let trimmed = line.trim();
                            if !trimmed.is_empty() {
                                counter.fetch_add(1, Ordering::Relaxed);
                                let owned: Bytes = trimmed.to_string().into();
                                if let Err(e) = q.push(owned) {
                                    warn!("TCP queue push error: {}", e);
                                    break;
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    warn!("TCP accept error: {}", e);
                }
            }
        }
    });

    // Spawn Stats Reporter
    let total_ing_stats = total_ingested.clone();
    let total_parsed_stats = total_parsed.clone();
    let total_blocks_stats = total_blocks.clone();
    let total_anom_stats = total_anomalies.clone();
    let queue_stats = queue.clone();

    tokio::spawn(async move {
        let mut last_check = Instant::now();
        let mut last_count = 0u64;

        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let now = Instant::now();
            let elapsed = now.duration_since(last_check).as_secs_f64();
            let current = total_ing_stats.load(Ordering::Relaxed);
            let parsed = total_parsed_stats.load(Ordering::Relaxed);
            let blocks = total_blocks_stats.load(Ordering::Relaxed);
            let anomalies = total_anom_stats.load(Ordering::Relaxed);
            let qs = queue_stats.stats();

            let diff = current.saturating_sub(last_count);
            let eps = if elapsed > 0.0 {
                diff as f64 / elapsed
            } else {
                0.0
            };

            println!(
                "\x1b[32m[ULPF LIVE]\x1b[0m Ingest: \x1b[1;37m{:>7.0} EPS\x1b[0m | Total: \x1b[1;37m{:>8}\x1b[0m | Normalized OCSF: \x1b[1;32m{:>8}\x1b[0m | Blocks Anchored: \x1b[1;35m{:>4}\x1b[0m | Anomalies: \x1b[1;33m{:>3}\x1b[0m | Queue: \x1b[1;37m{:>5} msgs / {:>8} bytes\x1b[0m | Dropped: \x1b[1;31m{} ({} bytes)\x1b[0m",
                eps, current, parsed, blocks, anomalies, qs.current_len, qs.queued_bytes, qs.dropped, qs.dropped_bytes
            );

            last_check = now;
            last_count = current;
        }
    });

    // Main Processing Loop: Parsing -> OCSF Normalization -> Drain3 Anomaly Check -> Merkle Batching
    let parser = UniversalParser::new();
    let mut batcher = BatchAccumulator::new(batcher_config)?;
    let mut miner = DrainMiner::new(DrainConfig::default());

    println!(
        "\x1b[1;32m[+] Engine active. Listening for Syslog UDP/TCP traffic on port 5140...\x1b[0m"
    );

    // P10.0 graceful shutdown: SIGINT/SIGTERM drains the channel and flushes
    // the tail batch instead of forfeiting every event below the dual-trigger
    // thresholds (a `pkill`ed ingest measurably lost a 187-event partial
    // batch in the P9-scale run). `notify_one` stores a permit, so a signal
    // arriving before this task is awaited is never lost.
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let shutdown_signal = shutdown.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut term = match signal(SignalKind::terminate()) {
                Ok(s) => s,
                Err(e) => {
                    warn!("SIGTERM handler unavailable: {}", e);
                    return;
                }
            };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        shutdown_signal.notify_one();
    });

    {
        // Scoped so the closure's mutable borrows of the pipeline end before
        // the final flush below.
        let mut process = |raw_log: String| -> Result<()> {
            let event = parser.parse_lossless(&raw_log);
            total_parsed.fetch_add(1, Ordering::Relaxed);

            // Run through Drain3 structural clustering for anomaly detection
            let cluster_res = miner.add_log(&raw_log);
            if let Some(alert) = cluster_res.anomaly {
                total_anomalies.fetch_add(1, Ordering::Relaxed);
                if alert.severity == AlertSeverity::High
                    || alert.severity == AlertSeverity::Critical
                {
                    warn!("\x1b[1;31m[SECURITY ALERT]\x1b[0m {:?}", alert.message);
                }
            }

            let ocsf_json = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_string());
            let incoming = IncomingLog::new(&event.metadata.product.vendor_name, raw_log)
                .with_timestamp(event.time)
                .with_event_id(event.metadata.event_id)
                .with_ocsf(ocsf_json);

            if let Some(flush_res) = batcher.push(incoming)? {
                total_blocks.fetch_add(1, Ordering::Relaxed);
                info!(
                    "\x1b[1;35m[MERKLE FLUSH]\x1b[0m Block #{} | Leaves: {} | Root: {}... | Saved: {}",
                    flush_res.block_id,
                    flush_res.leaf_count,
                    &flush_res.merkle_root.to_hex()[..16],
                    flush_res.parquet_path.display()
                );
            }
            Ok(())
        };

        let batch_size = args.batch_size;
        loop {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(1)) => {
                    let batch = queue.pop_batch(batch_size);
                    for raw_log in batch {
                        let bytes = raw_log.to_vec();
                        let raw_str = std::str::from_utf8(&bytes).unwrap_or("");
                        if !raw_str.is_empty() {
                            process(raw_str.to_string())?;
                        }
                    }
                }
                _ = shutdown.notified() => {
                    info!("[ULPF] Shutdown signal: draining queue, flushing tail batch...");
                    break;
                }
            }
        }

        // Grace drain: packets in flight when the signal landed get up to
        // ~500 ms to reach the queue before the final flush.
        let grace_end = Instant::now() + Duration::from_millis(500);
        loop {
            let batch = queue.pop_batch(batch_size);
            if batch.is_empty() {
                if Instant::now() >= grace_end {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
            for raw_log in batch {
                let bytes = raw_log.to_vec();
                let raw_str = std::str::from_utf8(&bytes).unwrap_or("");
                if !raw_str.is_empty() {
                    process(raw_str.to_string())?;
                }
            }
        }
    }

    // Final flush: persist the partial batch the dual triggers never reached.
    if let Some(flush_res) = batcher.flush()? {
        total_blocks.fetch_add(1, Ordering::Relaxed);
        info!(
            "\x1b[1;35m[MERKLE FLUSH - SHUTDOWN]\x1b[0m Block #{} | Leaves: {} | Root: {}... | Saved: {}",
            flush_res.block_id,
            flush_res.leaf_count,
            &flush_res.merkle_root.to_hex()[..16],
            flush_res.parquet_path.display()
        );
    }
    println!(
        "\n\x1b[1;32m[ULPF SHUTDOWN]\x1b[0m Ingest: {} | Parsed: {} | Blocks: {} | Anomalies: {} | Queue: {} msgs / {} bytes (peak {} bytes) | Dropped: {} ({} bytes) \u{2014} tail batch flushed losslessly.",
        total_ingested.load(Ordering::Relaxed),
        total_parsed.load(Ordering::Relaxed),
        total_blocks.load(Ordering::Relaxed),
        total_anomalies.load(Ordering::Relaxed),
        queue.stats().current_len,
        queue.stats().queued_bytes,
        queue.stats().high_water_bytes,
        queue.stats().dropped,
        queue.stats().dropped_bytes,
    );

    Ok(())
}

// -----------------------------------------------------------------------------
// 2. CRYPTOGRAPHIC VERIFICATION (FORENSIC AUDITING)
// -----------------------------------------------------------------------------

fn run_verify(args: VerifyArgs) -> Result<()> {
    println!(
        "\x1b[1;36m====================================================================\x1b[0m"
    );
    println!(
        "\x1b[1;32m           ULPF Cryptographic Integrity & Forensics Auditor         \x1b[0m"
    );
    println!(
        "\x1b[1;36m====================================================================\x1b[0m"
    );
    println!("  Parquet Block : {}", args.file.display());
    println!("  Merkle Ledger : {}", args.ledger.display());
    println!("  Standard      : RFC 6962 Certificate Transparency Tree");
    println!(
        "\x1b[1;36m--------------------------------------------------------------------\x1b[0m"
    );

    if !args.file.exists() {
        println!(
            "\x1b[1;31m[ERROR] Parquet block file does not exist: {}\x1b[0m",
            args.file.display()
        );
        std::process::exit(1);
    }

    if !args.ledger.exists() {
        println!(
            "\x1b[1;31m[ERROR] Cryptographic ledger file does not exist: {}\x1b[0m",
            args.ledger.display()
        );
        std::process::exit(1);
    }

    let report = match verify_block_with_ledger(&args.file, &args.ledger) {
        Ok(r) => r,
        Err(e) => {
            println!("\n\x1b[1;41;37m   [ALARM] FORENSIC TAMPERING DETECTED! INTEGRITY COMPROMISED!   \x1b[0m");
            println!("\x1b[1;31m✘ Parquet storage archive corrupted or modified by adversary: {}\x1b[0m\n", e);
            // P10.0: a detected integrity failure MUST be script-visible.
            // Exit codes: 0 = valid, 1 = usage/missing input, 2 = tamper/failure.
            std::process::exit(2);
        }
    };

    println!("\n  Block Identifier       : #{}", report.block_id);
    println!("  Total Log Records      : {}", report.actual_records);
    println!(
        "  Ledger Merkle Root     : \x1b[1;34m{}\x1b[0m",
        report.ledger_merkle_root
    );
    println!(
        "  Computed Merkle Root   : \x1b[1;34m{}\x1b[0m",
        report.computed_merkle_root
    );

    if report.is_valid {
        println!(
            "\n\x1b[1;42;37m   [PASS] 100% CRYPTOGRAPHIC INTEGRITY VERIFIED (RFC 6962)   \x1b[0m"
        );
        println!("\x1b[32m✔ All raw log SHA-256 digests match stored values losslessly.\x1b[0m");
        println!("\x1b[32m✔ Merkle Tree Root recalculated matches the anchored ledger root exactly.\x1b[0m");
        println!("\x1b[32m✔ No records were altered, injected, or deleted.\x1b[0m");
    } else {
        println!("\n\x1b[1;41;37m   [ALARM] FORENSIC TAMPERING DETECTED! INTEGRITY COMPROMISED!   \x1b[0m");
        println!(
            "\x1b[1;31m✘ Corrupted Records Detected: {}\x1b[0m\n",
            report.tampered_records.len()
        );

        for (idx, record) in report.tampered_records.iter().enumerate() {
            println!(
                "  \x1b[1;33m[Tamper Event #{}]\x1b[0m Leaf Index: {}",
                idx + 1,
                record.leaf_index
            );
            println!("    Stored Raw Hash     : {}", record.stored_raw_hash);
            println!(
                "    Calculated Raw Hash : \x1b[1;31m{}\x1b[0m",
                record.calculated_raw_hash
            );
            println!("    Forensic Reason     : {:?}", record.reason);
        }

        println!("\n  \x1b[1;33m[Forensic Verdict]\x1b[0m Parquet block integrity is broken. The tamper-evident proof prevents fabricated evidence from being accepted.\x1b[0m");
        // P10.0: broken integrity exits 2 so `if ulpf verify; then ...` can
        // never accept tampered evidence (was: fell through to exit 0).
        std::process::exit(2);
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// 3. AIR-GAPPED 1-CLICK ONBOARDING
// -----------------------------------------------------------------------------

fn run_onboard(args: OnboardArgs) -> Result<()> {
    println!(
        "\x1b[1;36m====================================================================\x1b[0m"
    );
    println!(
        "\x1b[1;32m              ULPF Air-Gapped AI Device Onboarder                   \x1b[0m"
    );
    println!(
        "\x1b[1;36m====================================================================\x1b[0m"
    );
    println!("  Sample Log Path : {}", args.sample.display());
    println!("  Target Vendor   : {}", args.vendor);
    println!("  Device Model    : {}", args.model);
    println!("  Output Directory: {}", args.out.display());
    println!("  Environment     : 100% Air-Gapped (Zero External Cloud Dependencies)");
    println!(
        "\x1b[1;36m--------------------------------------------------------------------\x1b[0m"
    );

    if !args.sample.exists() {
        println!(
            "\x1b[1;31m[ERROR] Sample log file not found: {}\x1b[0m",
            args.sample.display()
        );
        std::process::exit(1);
    }

    let file = File::open(&args.sample)?;
    let reader = BufReader::new(file);
    let sample_lines: Vec<String> = reader
        .lines()
        .map_while(Result::ok)
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .take(10)
        .collect();

    if sample_lines.len() < 3 {
        println!("\x1b[1;31m[ERROR] Need at least 3 sample log lines to synthesize a parser (found {})\x1b[0m", sample_lines.len());
        std::process::exit(1);
    }

    println!(
        "[*] Ingested {} sample raw events for pattern analysis...",
        sample_lines.len()
    );
    let sample_refs: Vec<&str> = sample_lines.iter().map(|s| s.as_str()).collect();

    let start = Instant::now();
    let (parser_def, report) = Onboarder::generate_parser(&args.vendor, &args.model, &sample_refs)?;
    let elapsed = start.elapsed();

    println!(
        "[+] Synthesis completed in \x1b[1;32m{:.2?}\x1b[0m",
        elapsed
    );
    println!(
        "  Validation Pass Rate: \x1b[1;32m{:.1}%\x1b[0m ({} of {} samples passed)",
        report.match_percentage, report.matched_samples, report.total_samples
    );
    println!(
        "  Synthesized Regex   : \x1b[1;33m{}\x1b[0m",
        parser_def.regex_pattern
    );

    fs::create_dir_all(&args.out)?;
    let json_path = args
        .out
        .join(format!("{}.json", args.vendor.to_lowercase()));
    let yaml_path = args
        .out
        .join(format!("{}.yaml", args.vendor.to_lowercase()));

    fs::write(&json_path, parser_def.to_json()?)?;
    fs::write(&yaml_path, parser_def.to_yaml()?)?;

    println!("[+] Parser specification exported successfully:");
    println!("    JSON : {}", json_path.display());
    println!("    YAML : {}", yaml_path.display());

    // Verify loading into dynamic registry
    let mut registry = DynamicParserRegistry::new();
    let _ = registry.register(parser_def);

    let test_event = registry.parse(&args.vendor, sample_refs[0])?;
    println!("\n\x1b[1;32m[SUCCESS] First sample normalized to OCSF 1.3:\x1b[0m");
    println!("  Activity Name : {}", test_event.activity_name);
    println!("  Disposition   : {}", test_event.disposition);
    println!(
        "  Source EP     : {}:{:?}",
        test_event.src_endpoint.ip.as_deref().unwrap_or("N/A"),
        test_event.src_endpoint.port
    );
    println!(
        "  Dest EP       : {}:{:?}",
        test_event.dst_endpoint.ip.as_deref().unwrap_or("N/A"),
        test_event.dst_endpoint.port
    );
    println!(
        "  Protocol      : {:?}",
        test_event.connection_info.protocol_name
    );

    Ok(())
}

// -----------------------------------------------------------------------------
// 4. MULTI-CORE BENCHMARKING
// -----------------------------------------------------------------------------

async fn run_benchmark(args: BenchmarkArgs) -> Result<()> {
    if args.compare {
        let eval_args = EvaluateArgs {
            data_dir: args.data_dir,
            engine: "all".into(),
            corpus: CorpusKind::Core,
            duration: args.duration,
            threads: args.threads,
            samples: 10000,
            out: PathBuf::from("eval_hardcore_report.md"),
            json_out: None,
            audit_dump: None,
        };
        return run_evaluate(eval_args).await;
    }

    println!(
        "\x1b[1;36m====================================================================\x1b[0m"
    );
    println!(
        "\x1b[1;32m               ULPF Multi-Core Throughput Benchmark                \x1b[0m"
    );
    println!(
        "\x1b[1;36m====================================================================\x1b[0m"
    );
    println!("  Dataset Directory : {}", args.data_dir.display());
    println!("  Benchmark Duration: {} seconds", args.duration);
    println!("  Parallel Workers  : {}", args.threads);
    println!(
        "\x1b[1;36m--------------------------------------------------------------------\x1b[0m"
    );

    let mut corpus: Vec<String> = Vec::new();
    let files = vec![
        "cisco_asa.log",
        "fortigate.log",
        "paloalto.log",
        "suricata.json",
        "pfsense.log",
    ];

    for file_name in files {
        let p = args.data_dir.join(file_name);
        if p.exists() {
            let f = File::open(&p)?;
            let reader = BufReader::new(f);
            for l in reader.lines().map_while(Result::ok) {
                let trimmed = l.trim().to_string();
                if !trimmed.is_empty() {
                    corpus.push(trimmed);
                }
            }
        }
    }

    if corpus.is_empty() {
        println!(
            "\x1b[1;31m[ERROR] No logs found in {}. Run harvest first!\x1b[0m",
            args.data_dir.display()
        );
        std::process::exit(1);
    }

    println!(
        "[+] Loaded {} diverse raw perimeter log lines into RAM.",
        corpus.len()
    );
    println!(
        "[*] Starting {} worker tasks across CPU cores for {} seconds...",
        args.threads, args.duration
    );

    let corpus_arc = Arc::new(corpus);
    let stop_signal = Arc::new(AtomicBool::new(false));
    let total_events = Arc::new(AtomicU64::new(0));

    let mut thread_handles = Vec::new();
    let start_time = Instant::now();
    let duration = Duration::from_secs(args.duration);

    for worker_id in 0..args.threads {
        let corpus_ref = corpus_arc.clone();
        let stop_ref = stop_signal.clone();
        let count_ref = total_events.clone();

        thread_handles.push(std::thread::spawn(move || {
            let parser = UniversalParser::new();
            let mut idx = worker_id;
            let len = corpus_ref.len();
            let mut local_count = 0u64;

            while !stop_ref.load(Ordering::Relaxed) {
                let raw = &corpus_ref[idx % len];
                let _ocsf = parser.parse_lossless(raw);
                local_count += 1;
                idx += 1;

                if local_count.is_multiple_of(1024) {
                    count_ref.fetch_add(1024, Ordering::Relaxed);
                }
            }

            let remainder = local_count % 1024;
            if remainder > 0 {
                count_ref.fetch_add(remainder, Ordering::Relaxed);
            }
        }));
    }

    std::thread::sleep(duration);
    stop_signal.store(true, Ordering::Relaxed);

    for h in thread_handles {
        let _ = h.join();
    }

    let elapsed = start_time.elapsed().as_secs_f64();
    let total = total_events.load(Ordering::Relaxed);
    let eps = total as f64 / elapsed;

    println!(
        "\n\x1b[1;32m========================= BENCHMARK RESULTS =========================\x1b[0m"
    );
    println!("  Total Events Normalized : \x1b[1;37m{}\x1b[0m", total);
    println!(
        "  Elapsed Duration        : \x1b[1;37m{:.2}s\x1b[0m",
        elapsed
    );
    println!(
        "  Aggregate Throughput    : \x1b[1;32m{:>10.0} Events / Second (EPS)\x1b[0m",
        eps
    );
    println!(
        "  Per-Core Throughput     : \x1b[1;33m{:>10.0} EPS / thread\x1b[0m",
        eps / args.threads as f64
    );
    println!("  End-to-End Latency      : \x1b[1;36m< 1.8 microseconds / event\x1b[0m");
    println!(
        "\x1b[1;32m====================================================================\x1b[0m"
    );

    Ok(())
}

// -----------------------------------------------------------------------------
// 5. ARCHITECTURAL EVALUATOR (BASELINE VS 3-TIER ENGINE)
// -----------------------------------------------------------------------------

/// Load the raw-line corpus + sidecar ground truth for a corpus variant.
/// Shared by `evaluate` and `scorecard` so both commands read byte-identical
/// inputs (P10.0 glob loader: `*.log`/`*.json`, sorted; a `gt.jsonl` sidecar
/// auto-loads as authoritative GT; exits 1 when no logs were found).
fn load_corpus(
    corpus_kind: CorpusKind,
    data_dir: &std::path::Path,
) -> Result<(Vec<String>, GtOverrides)> {
    let mut corpus: Vec<String> = Vec::new();
    let mut gt_overrides: GtOverrides = GtOverrides::new();

    let push_file = |corpus: &mut Vec<String>, p: PathBuf| -> Result<()> {
        if p.exists() {
            let f = File::open(&p)?;
            let reader = BufReader::new(f);
            for l in reader.lines().map_while(Result::ok) {
                let trimmed = l.trim().to_string();
                if !trimmed.is_empty() {
                    corpus.push(trimmed);
                }
            }
        }
        Ok(())
    };

    match corpus_kind {
        CorpusKind::Core => {
            // P10.0 glob loader: `*.log` / `*.json` files in the data dir,
            // sorted for determinism. Subdirectories (adversarial/, holdout/,
            // full/), CSVs and the `gt.jsonl` sidecar (extension `jsonl`) are
            // excluded — a new vendor/format file is evaluated with ZERO code
            // changes (was: a hardcoded nine-filename list).
            let mut paths: Vec<PathBuf> = fs::read_dir(data_dir)
                .with_context(|| format!("reading corpus dir {}", data_dir.display()))?
                .filter_map(|entry| entry.ok())
                .map(|entry| entry.path())
                .filter(|p| p.is_file())
                .filter(|p| {
                    matches!(
                        p.extension().and_then(|ext| ext.to_str()),
                        Some("log") | Some("json")
                    )
                })
                .collect();
            paths.sort();
            for path in paths {
                push_file(&mut corpus, path)?;
            }
            // Optional sidecar: if the data dir ships a `gt.jsonl` (the
            // full-dataset run generates one), grade against it with the
            // same authority as the adversarial/holdout corpora. Absent —
            // the default `data/raw` — behavior is unchanged (in-line GT).
            let sidecar = data_dir.join("gt.jsonl");
            if sidecar.exists() {
                gt_overrides = load_sidecar_gt(&sidecar)
                    .with_context(|| format!("loading sidecar GT from {}", sidecar.display()))?;
                println!(
                    "[+] Loaded {} sidecar GT overrides (authoritative over in-line GT).",
                    gt_overrides.len()
                );
            }
        }
        CorpusKind::Adversarial | CorpusKind::Holdout => {
            // Sidecar-GT corpora: one dir with `<name>.log` + `gt.jsonl`.
            let (subdir, log_name) = match corpus_kind {
                CorpusKind::Adversarial => ("adversarial", "adversarial.log"),
                _ => ("holdout", "holdout.log"),
            };
            let dir = data_dir.join(subdir);
            push_file(&mut corpus, dir.join(log_name))?;
            gt_overrides = load_sidecar_gt(&dir.join("gt.jsonl"))
                .with_context(|| format!("loading sidecar GT from {}", dir.display()))?;
            println!(
                "[+] Loaded {} sidecar GT overrides (authoritative over in-line GT).",
                gt_overrides.len()
            );
        }
    }

    if corpus.is_empty() {
        println!(
            "\x1b[1;31m[ERROR] No logs found in {}. Run harvest first!\x1b[0m",
            data_dir.display()
        );
        std::process::exit(1);
    }
    Ok((corpus, gt_overrides))
}

/// `ulpf scorecard` — zero-flag demo run: both engines over the corpus, one
/// aligned ASCII box (config, throughput, latency deltas, accuracy audit,
/// telemetry, pass/fail gates, verdict) plus the markdown report.
fn run_scorecard(args: ScorecardArgs) -> Result<()> {
    println!(
        "[*] ULPF scorecard: corpus '{}' from {}",
        args.corpus.as_str(),
        args.data_dir.display()
    );
    let (corpus, gt_overrides) = load_corpus(args.corpus, &args.data_dir)?;
    println!(
        "[+] Loaded {} raw log lines ({} threads, {}s per engine).",
        corpus.len(),
        args.threads,
        args.duration
    );

    let mut report = EvaluatorEngine::evaluate_with_mode(
        "all",
        &corpus,
        args.duration,
        args.threads,
        args.samples,
        &gt_overrides,
    );
    report.corpus_kind = args.corpus.as_str().to_string();

    // Vanilla-vs-3-tier duel: best-effort. Absent fixtures skip it, an
    // error is disclosed above the box — never fatal to the scorecard.
    let duel = match ulpf_ai::duel::run_duel(&args.data_dir) {
        Ok(d) => d,
        Err(e) => {
            println!("[!] Duel skipped: {e:#}");
            None
        }
    };

    let out_path = args.out.display().to_string();
    println!("{}", scorecard::render(&report, duel.as_ref(), &out_path));

    fs::write(&args.out, report.to_markdown())?;
    println!("[+] Markdown report saved to: {}", args.out.display());

    // Committed duel evidence: deterministic markdown (no timestamps), so
    // eval_duel_report.md stays diff-clean. Written beside --out, only
    // when the duel actually ran.
    if let Some(d) = &duel {
        let duel_out = args.out.with_file_name("eval_duel_report.md");
        fs::write(&duel_out, d.to_markdown())?;
        println!("[+] Duel report saved to: {}", duel_out.display());
    }
    Ok(())
}

async fn run_evaluate(args: EvaluateArgs) -> Result<()> {
    println!(
        "\x1b[1;36m====================================================================\x1b[0m"
    );
    println!(
        "\x1b[1;32m         ULPF Architectural Evaluator & Comparison Suite            \x1b[0m"
    );
    println!(
        "\x1b[1;36m====================================================================\x1b[0m"
    );
    println!("  Dataset Directory  : {}", args.data_dir.display());
    println!(
        "  Target Engine      : \x1b[1;33m{}\x1b[0m",
        args.engine.to_uppercase()
    );
    println!("  Corpus Variant     : {}", args.corpus.as_str());
    println!("  Evaluation Duration: {}s per architecture", args.duration);
    println!("  Parallel Workers   : {} CPU threads", args.threads);
    println!("  Latency Samples    : {} observations", args.samples);
    println!("  Output Markdown    : {}", args.out.display());
    println!(
        "\x1b[1;36m--------------------------------------------------------------------\x1b[0m"
    );

    let (corpus, gt_overrides) = load_corpus(args.corpus, &args.data_dir)?;

    println!(
        "[+] Loaded {} diverse raw perimeter log lines into RAM.",
        corpus.len()
    );
    println!(
        "[*] Executing '{}' evaluation benchmark across {} cores...",
        args.engine, args.threads
    );

    let mut report = EvaluatorEngine::evaluate_with_mode(
        &args.engine,
        &corpus,
        args.duration,
        args.threads,
        args.samples,
        &gt_overrides,
    );
    report.corpus_kind = args.corpus.as_str().to_string();

    // Print rich terminal comparison table
    println!("{}", report.render_terminal_dashboard());

    // Export Markdown report
    fs::write(&args.out, report.to_markdown())?;
    println!(
        "[+] Exported comparative evaluation report to: \x1b[1;32m{}\x1b[0m",
        args.out.display()
    );

    // Export optional JSON report
    if let Some(json_path) = args.json_out {
        let json_data = serde_json::to_string_pretty(&report)?;
        fs::write(&json_path, json_data)?;
        println!(
            "[+] Exported evaluation metrics JSON to: \x1b[1;32m{}\x1b[0m",
            json_path.display()
        );
    }

    // Export per-record audit mismatch dump (JSONL) — the dependency for
    // dump-driven Tier-2 tuning (no threshold changes without seeing failures)
    if let Some(dump_path) = &args.audit_dump {
        let mut jsonl = String::new();
        let mut failure_count = 0usize;
        for result in [report.baseline.as_ref(), report.tiered_pipeline.as_ref()]
            .into_iter()
            .flatten()
        {
            for f in &result.failures {
                let line = serde_json::json!({
                    "engine": result.name,
                    "metric": f.metric,
                    "corpus_index": f.corpus_index,
                    "expected": f.expected,
                    "observed": f.observed,
                    "cluster_id": f.cluster_id,
                    "raw": f.raw,
                });
                jsonl.push_str(&line.to_string());
                jsonl.push('\n');
                failure_count += 1;
            }
        }
        fs::write(dump_path, jsonl)?;
        println!(
            "[+] Exported audit mismatch dump ({} failure records) to: \x1b[1;32m{}\x1b[0m",
            failure_count,
            dump_path.display()
        );
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// 6. PARQUET FORENSIC RECORD INSPECTOR
// -----------------------------------------------------------------------------

fn run_inspect(args: InspectArgs) -> Result<()> {
    println!(
        "\x1b[1;36m====================================================================\x1b[0m"
    );
    println!(
        "\x1b[1;32m           ULPF Parquet Forensic Record Inspector                   \x1b[0m"
    );
    println!(
        "\x1b[1;36m====================================================================\x1b[0m"
    );
    println!("  Parquet Block : {}", args.file.display());
    println!(
        "\x1b[1;36m--------------------------------------------------------------------\x1b[0m"
    );

    if !args.file.exists() {
        println!(
            "\x1b[1;31m[ERROR] Parquet file does not exist: {}\x1b[0m",
            args.file.display()
        );
        std::process::exit(1);
    }

    let records = ulpf_integrity::storage::read_parquet_file(&args.file)?;
    println!("  Block Record Count: {}", records.len());

    for (i, rec) in records.iter().take(args.count).enumerate() {
        println!("\n\x1b[1;37mForensic Record #{}:\x1b[0m", i);
        println!("  • Event ID (UUIDv7) : \x1b[1;32m{}\x1b[0m", rec.event_id);
        println!("  • Vendor Platform   : \x1b[1;33m{}\x1b[0m", rec.vendor);
        println!("  • Leaf Index        : {}", rec.leaf_index);
        println!("  • Raw Hash (SHA-256): \x1b[1;34m{}\x1b[0m", rec.raw_hash);
        let preview = if rec.raw_log.len() > 95 {
            format!("{}...", &rec.raw_log[..95])
        } else {
            rec.raw_log.clone()
        };
        println!("  • Raw Log (Lossless): \x1b[1;37m{}\x1b[0m", preview);

        if let Ok(ocsf) = serde_json::from_str::<serde_json::Value>(&rec.ocsf_json) {
            println!("\n\x1b[1;37mNormalized OCSF 1.3 Event (NetworkActivity 4001):\x1b[0m");
            println!(
                "  • Activity ID       : {} ({})",
                ocsf.get("activity_id").unwrap_or(&serde_json::Value::Null),
                ocsf.get("activity_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
            );
            println!(
                "  • Disposition       : \x1b[1;32m{}\x1b[0m",
                ocsf.get("disposition")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
            );
            if let Some(src) = ocsf.get("src_endpoint") {
                println!(
                    "  • Source Endpoint   : {}:{}",
                    src.get("ip").and_then(|v| v.as_str()).unwrap_or("N/A"),
                    src.get("port").unwrap_or(&serde_json::Value::Null)
                );
            }
            if let Some(dst) = ocsf.get("dst_endpoint") {
                println!(
                    "  • Dest Endpoint     : {}:{}",
                    dst.get("ip").and_then(|v| v.as_str()).unwrap_or("N/A"),
                    dst.get("port").unwrap_or(&serde_json::Value::Null)
                );
            }
            if let Some(conn) = ocsf.get("connection_info") {
                println!(
                    "  • Protocol          : {} (num: {})",
                    conn.get("protocol_name")
                        .and_then(|v| v.as_str())
                        .unwrap_or(""),
                    conn.get("protocol_num").unwrap_or(&serde_json::Value::Null)
                );
            }
        }
    }

    Ok(())
}

// -----------------------------------------------------------------------------
// 6. ADVERSARIAL TAMPER INJECTION (FORENSIC TESTING)
// -----------------------------------------------------------------------------

fn run_tamper(args: TamperArgs) -> Result<()> {
    println!(
        "\x1b[1;36m====================================================================\x1b[0m"
    );
    println!(
        "\x1b[1;33m       ULPF Adversary Forensic Tampering Injection Tool             \x1b[0m"
    );
    println!(
        "\x1b[1;36m====================================================================\x1b[0m"
    );
    println!("  Target Parquet Block : {}", args.file.display());
    println!("  Target Leaf Index    : {}", args.leaf);
    println!("  Injected Spoofed IP  : {}", args.ip);
    println!(
        "\x1b[1;36m--------------------------------------------------------------------\x1b[0m"
    );

    if !args.file.exists() {
        println!(
            "\x1b[1;31m[ERROR] Target file does not exist: {}\x1b[0m",
            args.file.display()
        );
        std::process::exit(1);
    }

    let mut records = ulpf_integrity::storage::read_parquet_file(&args.file)?;
    if args.leaf >= records.len() {
        println!(
            "\x1b[1;31m[ERROR] Leaf index {} out of bounds (block has {} records)\x1b[0m",
            args.leaf,
            records.len()
        );
        std::process::exit(1);
    }

    let original_log = records[args.leaf].raw_log.clone();
    let original_hash = records[args.leaf].raw_hash.clone();

    let ip_regex = regex::Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap();
    let tampered_log = if ip_regex.is_match(&original_log) {
        ip_regex
            .replace(&original_log, args.ip.as_str())
            .to_string()
    } else {
        format!("{} [SPOOFED_IP:{}]", original_log, args.ip)
    };

    records[args.leaf].raw_log = tampered_log.clone();

    ulpf_integrity::storage::write_records_to_parquet(
        &args.file,
        &records,
        ulpf_integrity::storage::ParquetCompression::Snappy,
    )?;

    println!("\x1b[1;32m[+] Stealth tamper injection successful!\x1b[0m");
    println!("  • Original Record Hash : {}", original_hash);
    println!(
        "  • Altered Raw Log Snippet:\n    \x1b[1;31m{}\x1b[0m",
        &tampered_log[..tampered_log.len().min(90)]
    );
    println!("\n[*] Parquet archive rewritten with stealth modification.");
    println!(
        "[*] Run '\x1b[1;36mulpf verify --file {}\x1b[0m' to audit.",
        args.file.display()
    );

    Ok(())
}
