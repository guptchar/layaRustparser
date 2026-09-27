use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::Instant;

use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use chrono::Utc;
use flate2::write::GzEncoder;
use flate2::Compression;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tar::Builder;
use uuid::Uuid;

use super::state::{AlertItem, AppState, MetricsResponse};
use ulpf_ai::drain::AlertSeverity;
use ulpf_ai::onboarder::{Onboarder, ParserDefinition, ValidationReport};
use ulpf_core::parser::UniversalParser;
use ulpf_core::schema::ocsf::NetworkActivity;
use ulpf_integrity::batcher::BatchAccumulator;
use ulpf_integrity::merkle::{MerkleTree, Side};
use ulpf_integrity::storage::{read_parquet_file, write_records_to_parquet, ParquetCompression};
use ulpf_integrity::tamper::{verify_block_with_ledger, TamperReport};

// -----------------------------------------------------------------------------
// Request / Response DTOs
// -----------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: u16,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_index: Option<usize>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockItem {
    pub block_id: u64,
    pub timestamp: i64,
    pub leaf_count: usize,
    pub merkle_root: String,
    pub parquet_file: String,
    pub status: String,
    pub size_bytes: u64,
    pub file_exists: bool,
}

#[derive(Debug, Deserialize)]
pub struct RecordsQuery {
    pub offset: Option<usize>,
    pub limit: Option<usize>,
    pub vendor: Option<String>,
    pub disposition: Option<String>,
    pub ip: Option<String>,
    pub query: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StoredRecordItem {
    pub event_id: String,
    pub block_id: u64,
    pub leaf_index: u32,
    pub timestamp: i64,
    pub vendor: String,
    pub raw_log: String,
    pub raw_hash: String,
    pub ocsf: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BlockRecordsResponse {
    pub block_id: u64,
    pub total_records_in_block: usize,
    pub filtered_records_count: usize,
    pub offset: usize,
    pub limit: usize,
    pub records: Vec<StoredRecordItem>,
}

#[derive(Debug, Deserialize)]
pub struct ProveQuery {
    pub live: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditStep {
    pub hash: String,
    pub side: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InclusionProofResponse {
    pub block_id: u64,
    pub leaf_index: usize,
    pub tree_size: usize,
    pub leaf_hash: String,
    pub calculated_merkle_root: String,
    pub ledger_merkle_root: Option<String>,
    pub verified: bool,
    pub audit_path: Vec<AuditStep>,
    pub standard: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ParserItem {
    pub vendor: String,
    pub device_model: String,
    pub parser_type: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub regex_pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence_score: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ParserTestRequest {
    pub raw_log: String,
    pub vendor: Option<String>,
    pub regex_pattern: Option<String>,
    pub action_mappings: Option<HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ParserTestResponse {
    pub matched: bool,
    pub vendor: String,
    pub parsed_ocsf: Option<NetworkActivity>,
    pub parse_duration_micros: f64,
    pub raw_hash: String,
    pub protocol_detected: Option<String>,
    pub notes: String,
}

#[derive(Debug, Deserialize)]
pub struct OnboardRequest {
    pub vendor: String,
    #[serde(default = "default_device_model")]
    pub device_model: String,
    pub sample_lines: Vec<String>,
    #[serde(default)]
    pub confirm: bool,
}

fn default_device_model() -> String {
    "generic".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OnboardResponse {
    pub status: String,
    pub persisted: bool,
    pub vendor: String,
    pub device_model: String,
    pub parser_definition: ParserDefinition,
    pub validation_report: ValidationReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yaml_path: Option<String>,
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct TamperDrillRequest {
    pub block_id: u64,
    #[serde(default)]
    pub leaf_index: usize,
    #[serde(default = "default_spoofed_ip")]
    pub spoofed_ip: String,
    #[serde(default)]
    pub confirm: bool,
}

fn default_spoofed_ip() -> String {
    "10.99.99.99".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TamperDrillResponse {
    pub status: String,
    pub executed: bool,
    pub target_block_id: u64,
    pub target_leaf_index: usize,
    pub spoofed_ip: String,
    pub source_evidence_path: String,
    pub scratch_drill_path: String,
    pub original_evidence_unmodified: bool,
    pub tamper_report: Option<TamperReport>,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatcherConfigDisplay {
    pub max_batch_size: usize,
    pub max_batch_duration_ms: u64,
    pub storage_dir: String,
    pub ledger_path: String,
    pub compression: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemResponse {
    pub service_name: String,
    pub version: String,
    pub air_gapped: bool,
    pub uptime_secs: u64,
    pub batcher: BatcherConfigDisplay,
    pub ingest_queue_capacity: usize,
    pub ingest_queue_depth: usize,
    pub dynamic_parsers_loaded: usize,
    pub total_archived_blocks: usize,
    pub benchmark_summary: Option<serde_json::Value>,
}

// -----------------------------------------------------------------------------
// Endpoint Handlers
// -----------------------------------------------------------------------------

/// GET /metrics
pub async fn get_metrics(State(state): State<AppState>) -> Json<MetricsResponse> {
    Json(state.compute_metrics())
}

/// GET /alerts
pub async fn get_alerts(State(state): State<AppState>) -> Json<Vec<AlertItem>> {
    let alerts = state.alerts.read().await;
    Json(alerts.clone())
}

/// GET /blocks
pub async fn get_blocks(State(state): State<AppState>) -> Json<Vec<BlockItem>> {
    let mut items = Vec::new();

    if state.ledger_path.exists() {
        if let Ok(entries) = BatchAccumulator::load_ledger_entries(&state.ledger_path) {
            for entry in entries {
                let block_filename = format!("block_{:05}.parquet", entry.block_id);
                let p = state.parquet_dir.join(&block_filename);
                let exists = p.exists();
                let size_bytes = if exists {
                    std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0)
                } else {
                    0
                };

                // Determine audit status
                let status = if !exists {
                    "FILE_MISSING".to_string()
                } else if let Ok(report) = verify_block_with_ledger(&p, &state.ledger_path) {
                    if report.is_valid {
                        "PASS".to_string()
                    } else {
                        "FAIL".to_string()
                    }
                } else {
                    "UNAUDITED".to_string()
                };

                items.push(BlockItem {
                    block_id: entry.block_id,
                    timestamp: entry.timestamp,
                    leaf_count: entry.leaf_count,
                    merkle_root: entry.merkle_root,
                    parquet_file: block_filename,
                    status,
                    size_bytes,
                    file_exists: exists,
                });
            }
        }
    }

    Json(items)
}

/// GET /blocks/:id/records
pub async fn get_block_records(
    AxumPath(block_id): AxumPath<u64>,
    Query(query): Query<RecordsQuery>,
    State(state): State<AppState>,
) -> Result<Json<BlockRecordsResponse>, (StatusCode, Json<ErrorResponse>)> {
    let filename = format!("block_{:05}.parquet", block_id);
    let path = state.parquet_dir.join(&filename);

    if !path.exists() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Not Found".to_string(),
                code: 404,
                message: format!(
                    "Parquet block #{} does not exist at {}",
                    block_id,
                    path.display()
                ),
                block_id: Some(block_id),
                leaf_index: None,
            }),
        ));
    }

    let records = read_parquet_file(&path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Read Error".to_string(),
                code: 500,
                message: format!("Failed reading Parquet block #{}: {}", block_id, e),
                block_id: Some(block_id),
                leaf_index: None,
            }),
        )
    })?;

    let total_in_block = records.len();

    // Filtering
    let filtered: Vec<_> = records
        .into_iter()
        .filter(|r| {
            if let Some(ref v) = query.vendor {
                if !r.vendor.eq_ignore_ascii_case(v) {
                    return false;
                }
            }
            if let Some(ref q) = query.query {
                let q_lower = q.to_lowercase();
                if !r.raw_log.to_lowercase().contains(&q_lower)
                    && !r.event_id.to_lowercase().contains(&q_lower)
                    && !r.raw_hash.to_lowercase().contains(&q_lower)
                {
                    return false;
                }
            }
            if let Some(ref ip) = query.ip {
                if !r.raw_log.contains(ip) {
                    return false;
                }
            }
            if let Some(ref disp) = query.disposition {
                let matches = serde_json::from_str::<serde_json::Value>(&r.ocsf_json)
                    .ok()
                    .and_then(|val| {
                        val.get("disposition")
                            .and_then(|v| v.as_str().map(|s| s.to_string()))
                    })
                    .is_some_and(|d| d.eq_ignore_ascii_case(disp));
                if !matches {
                    return false;
                }
            }
            true
        })
        .collect();

    let filtered_count = filtered.len();
    let offset = query.offset.unwrap_or(0);
    let limit = query.limit.unwrap_or(50).clamp(1, 500);

    let page_records: Vec<StoredRecordItem> = filtered
        .into_iter()
        .skip(offset)
        .take(limit)
        .map(|r| {
            let ocsf = serde_json::from_str::<serde_json::Value>(&r.ocsf_json)
                .unwrap_or_else(|_| serde_json::json!({ "raw": r.raw_log }));
            StoredRecordItem {
                event_id: r.event_id,
                block_id: r.block_id,
                leaf_index: r.leaf_index,
                timestamp: r.timestamp,
                vendor: r.vendor,
                raw_log: r.raw_log,
                raw_hash: r.raw_hash,
                ocsf,
            }
        })
        .collect();

    Ok(Json(BlockRecordsResponse {
        block_id,
        total_records_in_block: total_in_block,
        filtered_records_count: filtered_count,
        offset,
        limit,
        records: page_records,
    }))
}

/// GET /prove/:block/:leaf
pub async fn get_prove_inclusion(
    AxumPath((block_id, leaf_index)): AxumPath<(u64, usize)>,
    Query(query): Query<ProveQuery>,
    State(state): State<AppState>,
) -> Result<Json<InclusionProofResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Check if live evaluation was requested
    if query.live != Some(true) {
        // Acceptance criteria for Issue #12:
        // "GET /prove/:block/:leaf (needs [integrity/M] Ledger fsync + prove/consistency CLI #5, else stub with 501 + message)"
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            Json(ErrorResponse {
                error: "Not Implemented".to_string(),
                code: 501,
                message: "Merkle inclusion proof endpoint is stubbed pending completion of #5 ([integrity/M] Ledger fsync + prove/consistency CLI). Pass '?live=true' to execute live RFC 6962 audit path computation.".to_string(),
                block_id: Some(block_id),
                leaf_index: Some(leaf_index),
            }),
        ));
    }

    // Live RFC 6962 inclusion proof calculation
    let filename = format!("block_{:05}.parquet", block_id);
    let path = state.parquet_dir.join(&filename);

    if !path.exists() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Not Found".to_string(),
                code: 404,
                message: format!("Parquet file for block #{} not found", block_id),
                block_id: Some(block_id),
                leaf_index: Some(leaf_index),
            }),
        ));
    }

    let records = read_parquet_file(&path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Read Error".to_string(),
                code: 500,
                message: format!("Failed reading block records: {}", e),
                block_id: Some(block_id),
                leaf_index: Some(leaf_index),
            }),
        )
    })?;

    if leaf_index >= records.len() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Index Out of Bounds".to_string(),
                code: 400,
                message: format!(
                    "Leaf index {} is out of bounds (block #{} has {} records)",
                    leaf_index,
                    block_id,
                    records.len()
                ),
                block_id: Some(block_id),
                leaf_index: Some(leaf_index),
            }),
        ));
    }

    let raw_logs: Vec<&[u8]> = records.iter().map(|r| r.raw_log.as_bytes()).collect();
    let tree = MerkleTree::from_raw_logs(raw_logs);
    let calculated_root = tree.root_hex();

    let proof = tree.inclusion_proof(leaf_index).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Proof Generation Error".to_string(),
                code: 500,
                message: format!("Failed generating inclusion proof: {}", e),
                block_id: Some(block_id),
                leaf_index: Some(leaf_index),
            }),
        )
    })?;

    // Load ledger root if ledger file is present
    let ledger_root = if state.ledger_path.exists() {
        BatchAccumulator::load_ledger_entries(&state.ledger_path)
            .ok()
            .and_then(|entries| {
                entries
                    .into_iter()
                    .find(|e| e.block_id == block_id)
                    .map(|e| e.merkle_root)
            })
    } else {
        None
    };

    let target_hash = ulpf_integrity::merkle::hash_leaf(records[leaf_index].raw_log.as_bytes());
    let verified = ulpf_integrity::merkle::verify_inclusion_proof_by_hash(
        &target_hash,
        proof.leaf_index,
        proof.tree_size,
        &proof.audit_path,
        &tree.root(),
    );

    let audit_steps: Vec<AuditStep> = proof
        .audit_path
        .into_iter()
        .map(|(h, s)| AuditStep {
            hash: h.to_hex(),
            side: match s {
                Side::Left => "Left".to_string(),
                Side::Right => "Right".to_string(),
            },
        })
        .collect();

    Ok(Json(InclusionProofResponse {
        block_id,
        leaf_index,
        tree_size: records.len(),
        leaf_hash: target_hash.to_hex(),
        calculated_merkle_root: calculated_root,
        ledger_merkle_root: ledger_root,
        verified,
        audit_path: audit_steps,
        standard: "RFC 6962 Certificate Transparency Standard".to_string(),
    }))
}

/// GET /parsers
pub async fn get_parsers(State(state): State<AppState>) -> Json<Vec<ParserItem>> {
    let mut items = Vec::new();

    // 1. Built-in native zero-copy extractors
    let native_vendors = [
        ("cisco_asa", "ASA 5500-X / Firepower"),
        ("fortigate", "FortiGate NGFW (v7.0+)"),
        ("paloalto", "PAN-OS (PA-Series)"),
        ("pfsense", "pfSense filterlog (IPv4/IPv6)"),
        ("suricata", "Suricata EVE-JSON"),
        ("cef", "Common Event Format (CEF:0)"),
    ];

    for (v, model) in native_vendors {
        items.push(ParserItem {
            vendor: v.to_string(),
            device_model: model.to_string(),
            parser_type: "native_extractor".to_string(),
            status: "active".to_string(),
            regex_pattern: None,
            confidence_score: Some(1.0),
            created_at: None,
        });
    }

    // 2. Dynamic onboarded parsers from data/parsers/
    if state.parsers_dir.exists() {
        if let Ok(entries) = std::fs::read_dir(&state.parsers_dir) {
            for entry in entries.flatten() {
                let p = entry.path();
                if !p.is_file() {
                    continue;
                }
                if p.extension().and_then(|s| s.to_str()) != Some("json") {
                    continue;
                }
                // A file that exists but cannot be used is REPORTED, not
                // skipped. Both failure modes were previously invisible here:
                // an unparseable file simply vanished from the listing, and a
                // file whose `regex_pattern` does not compile was listed as
                // `active` even though it can never match an event. An operator
                // reading this endpoint has no other way to tell a working
                // parser from a dead one.
                let item = match std::fs::read_to_string(&p) {
                    Err(_) => ParserItem {
                        vendor: "<unreadable>".to_string(),
                        device_model: p.display().to_string(),
                        parser_type: "dynamic_onboarded".to_string(),
                        status: "unreadable".to_string(),
                        regex_pattern: None,
                        confidence_score: None,
                        created_at: None,
                    },
                    Ok(content) => match ParserDefinition::from_json(&content) {
                        Err(_) => ParserItem {
                            vendor: "<malformed>".to_string(),
                            device_model: p.display().to_string(),
                            parser_type: "dynamic_onboarded".to_string(),
                            status: "malformed".to_string(),
                            regex_pattern: None,
                            confidence_score: None,
                            created_at: None,
                        },
                        Ok(def) => {
                            let status = if Regex::new(&def.regex_pattern).is_ok() {
                                "active"
                            } else {
                                "invalid"
                            };
                            ParserItem {
                                vendor: def.vendor,
                                device_model: def.device_model,
                                parser_type: "dynamic_onboarded".to_string(),
                                status: status.to_string(),
                                regex_pattern: Some(def.regex_pattern),
                                confidence_score: Some(def.confidence_score),
                                created_at: Some(def.created_at),
                            }
                        }
                    },
                };
                items.push(item);
            }
        }
    }

    Json(items)
}

/// POST /parsers/test
/// Dry-run test of a single raw log line against dynamic registry or custom regex.
/// Never writes to disk.
pub async fn post_parsers_test(
    State(state): State<AppState>,
    Json(payload): Json<ParserTestRequest>,
) -> Result<Json<ParserTestResponse>, (StatusCode, Json<ErrorResponse>)> {
    let start = Instant::now();
    let raw = payload.raw_log.trim();

    if raw.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Bad Request".to_string(),
                code: 400,
                message: "Field 'raw_log' cannot be empty".to_string(),
                block_id: None,
                leaf_index: None,
            }),
        ));
    }

    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let raw_hash = hex::encode(hasher.finalize());

    // Detect protocol evidence (HTTP/1.1 & HTTP/2 -> TCP 6; HTTP/3 & QUIC -> UDP 17)
    let protocol_detected =
        if raw.to_lowercase().contains("http3") || raw.to_lowercase().contains("quic") {
            Some("HTTP/3 (QUIC / UDP)".to_string())
        } else if raw.to_lowercase().contains("http2") || raw.to_lowercase().contains("h2") {
            Some("HTTP/2 (TCP)".to_string())
        } else if raw.to_lowercase().contains("http") {
            Some("HTTP/1.1 (TCP)".to_string())
        } else {
            None
        };

    // Case 1: Custom regex test
    if let Some(ref pattern) = payload.regex_pattern {
        let re = regex::Regex::new(pattern).map_err(|e| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid Regex".to_string(),
                    code: 400,
                    message: format!("Provided regex pattern failed to compile: {}", e),
                    block_id: None,
                    leaf_index: None,
                }),
            )
        })?;

        let matched = re.is_match(raw);
        let vendor = payload
            .vendor
            .unwrap_or_else(|| "custom_test_device".to_string());

        // Reuse the `re` already compiled above instead of recompiling the
        // same pattern inside the definition's cache.
        //
        // `matched` and `parsed_ocsf` are genuinely different questions, and
        // this response has to answer both. A pattern can match the line and
        // still fail extraction — most often because a `src_ip`/`dst_ip` group
        // captured something that is not an address, which `parse_with_regex`
        // rejects rather than filing the event under a fabricated endpoint. A
        // bare `parsed_ocsf: null` reads as "no event", so the reason travels
        // in `notes` instead of being dropped on the floor.
        let (parsed_ocsf, extraction_error) = if matched {
            let def = ParserDefinition {
                vendor: vendor.clone(),
                device_model: "test_model".to_string(),
                regex_pattern: pattern.clone(),
                action_mappings: payload.action_mappings.clone().unwrap_or_default(),
                sample_logs: vec![raw.to_string()],
                confidence_score: 1.0,
                created_at: Utc::now().timestamp_millis(),
                regex_cache: std::sync::Arc::new(std::sync::OnceLock::new()),
            };
            match def.parse_with_regex(&re, raw) {
                Ok(ev) => (Some(ev), None),
                Err(e) => (None, Some(e.to_string())),
            }
        } else {
            (None, None)
        };

        let duration = start.elapsed().as_secs_f64() * 1_000_000.0;
        let notes = match extraction_error {
            Some(reason) => format!(
                "Ad-hoc regex dry-run (read-only, no disk mutations). The pattern MATCHED the \
                 line but extraction was REJECTED: {reason}"
            ),
            None => "Ad-hoc regex dry-run completed (read-only, no disk mutations)".to_string(),
        };
        return Ok(Json(ParserTestResponse {
            matched,
            vendor,
            parsed_ocsf,
            parse_duration_micros: (duration * 10.0).round() / 10.0,
            raw_hash,
            protocol_detected,
            notes,
        }));
    }

    // Case 2: Parse through dynamic registry
    let mut reg = state.registry.write().await;
    let vendor = payload.vendor.as_deref().unwrap_or("universal");

    let parsed_ocsf = if let Ok(event) = reg.parse(vendor, raw) {
        Some(event)
    } else {
        // Fallback to UniversalParser baseline
        let universal = UniversalParser::new();
        Some(universal.parse_lossless(raw))
    };

    let duration = start.elapsed().as_secs_f64() * 1_000_000.0;

    Ok(Json(ParserTestResponse {
        matched: parsed_ocsf.is_some(),
        vendor: vendor.to_string(),
        parsed_ocsf,
        parse_duration_micros: (duration * 10.0).round() / 10.0,
        raw_hash,
        protocol_detected,
        notes: "Parsed through dynamic registry / universal baseline (read-only)".to_string(),
    }))
}

/// Temp-file disambiguator so concurrent onboard requests never share a name.
static PUBLISH_TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Atomically publish the JSON+YAML parser pair.
///
/// Both payloads are written to temp files in the SAME directory, then
/// `rename`d over their targets. `rename(2)` is atomic on POSIX: readers
/// (e.g. `GET /parsers`) never observe a half-written definition, and a
/// crash between the two renames leaves at worst one stale-but-whole file —
/// never a truncated one. Temps live beside their targets so the rename
/// stays on one filesystem (no cross-device hop).
///
/// On any failure the temp files are removed and any already-renamed target
/// is rolled back to its prior contents (or removed if it did not exist),
/// so there is no window where only one half of the pair exists.
///
/// A rollback that itself fails is NOT swallowed: the returned error names
/// both the original publish failure and whatever could not be undone, because
/// silently reporting only the first would leave a caller believing the
/// directory is clean when it is not.
fn publish_parser_pair(
    dir: &std::path::Path,
    json_file: &str,
    yaml_file: &str,
    json_str: &str,
    yaml_str: &str,
) -> std::io::Result<()> {
    let json_path = dir.join(json_file);
    let yaml_path = dir.join(yaml_file);

    // Snapshot BEFORE touching anything, so a rollback restores rather than
    // deletes a parser that was already published.
    //
    // Tri-state, deliberately. `read(..).ok()` collapses "no file there" and
    // "the file is there but unreadable" into the same `None`, and the rollback
    // below deletes on `None` — so an unreadable existing parser (bad
    // permissions, transient I/O error) would have been DELETED on failure
    // rather than restored. The three cases need three answers.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Prior {
        /// Existed; these are its bytes.
        Present,
        /// Did not exist, so a rollback should remove whatever landed.
        Absent,
        /// Existed but could not be read. Contents unknown — a rollback must
        /// not guess, and must not delete.
        Unreadable,
    }
    let snapshot = |path: &std::path::Path| -> (Option<Vec<u8>>, Prior) {
        match std::fs::read(path) {
            Ok(bytes) => (Some(bytes), Prior::Present),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (None, Prior::Absent),
            Err(_) => (None, Prior::Unreadable),
        }
    };
    let (prior_json, state_json) = snapshot(&json_path);
    let (prior_yaml, state_yaml) = snapshot(&yaml_path);

    let tag = format!(
        "tmp-{}-{}",
        std::process::id(),
        PUBLISH_TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let json_tmp = dir.join(format!("{json_file}.{tag}"));
    let yaml_tmp = dir.join(format!("{yaml_file}.{tag}"));

    // Clean up the temps, then undo any rename that already happened. Targets
    // that were never renamed are untouched — the originals are still whole on
    // disk. Restores go through their own temp + rename for the same reason the
    // publish does: a plain `write` to the target truncates it first, so a
    // failed restore would leave the previous definition destroyed rather than
    // merely unreverted.
    let rollback = |json_renamed: bool, yaml_renamed: bool| -> std::io::Result<()> {
        let mut problems: Vec<String> = Vec::new();
        // A temp that is already gone is the EXPECTED case, not a problem: the
        // half that renamed successfully no longer has one. Reporting it would
        // make every clean rollback claim to be incomplete.
        let mut drop_temp = |r: std::io::Result<()>, what: &str| match r {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => problems.push(format!("{what}: {e}")),
            Ok(()) => {}
        };

        drop_temp(std::fs::remove_file(&json_tmp), "temp json");
        drop_temp(std::fs::remove_file(&yaml_tmp), "temp yaml");
        for (path, prior, prior_state, renamed, what) in [
            (&json_path, &prior_json, state_json, json_renamed, "json"),
            (&yaml_path, &prior_yaml, state_yaml, yaml_renamed, "yaml"),
        ] {
            if !renamed {
                continue;
            }
            match prior_state {
                Prior::Present => {
                    let bytes = prior.as_ref().expect("Present implies Some");
                    let restore_tmp = dir.join(format!(
                        "{}.rollback-{tag}",
                        path.file_name().unwrap_or_default().to_string_lossy()
                    ));
                    if let Err(e) = std::fs::write(&restore_tmp, bytes)
                        .and_then(|()| std::fs::rename(&restore_tmp, path))
                    {
                        problems.push(format!("{what}: {e}"));
                    }
                }
                Prior::Absent => {
                    if let Err(e) = std::fs::remove_file(path) {
                        problems.push(format!("{what}: {e}"));
                    }
                }
                Prior::Unreadable => {
                    // The prior contents are unknown, so neither restoring nor
                    // deleting is defensible. Leave the new content in place —
                    // the file is at least valid — and say the rollback is
                    // incomplete so the operator knows to reconcile it.
                    problems.push(format!(
                        "{what}: could not read the prior file before publishing, so it was \
                         not restored; it now holds the new definition"
                    ));
                }
            }
        }
        if problems.is_empty() {
            Ok(())
        } else {
            Err(std::io::Error::other(problems.join("; ")))
        }
    };

    // Stage BOTH payloads before either becomes visible: a failure here
    // leaves the originals untouched.
    let fail = |e: std::io::Error, json_renamed: bool, yaml_renamed: bool| match rollback(
        json_renamed,
        yaml_renamed,
    ) {
        Ok(()) => e,
        Err(rollback_err) => std::io::Error::other(format!(
            "publish failed: {e}; and the rollback was incomplete: {rollback_err}"
        )),
    };

    if let Err(e) =
        std::fs::write(&json_tmp, json_str).and_then(|()| std::fs::write(&yaml_tmp, yaml_str))
    {
        return Err(fail(e, false, false));
    }
    if let Err(e) = std::fs::rename(&json_tmp, &json_path) {
        return Err(fail(e, false, false));
    }
    if let Err(e) = std::fs::rename(&yaml_tmp, &yaml_path) {
        return Err(fail(e, true, false));
    }
    Ok(())
}

/// POST /onboard
/// 1-Click air-gapped onboarding wizard.
/// If `confirm: false`, returns synthesis preview without writing to disk.
/// If `confirm: true`, writes parser files and hot-loads into dynamic registry.
pub async fn post_onboard(
    State(state): State<AppState>,
    Json(payload): Json<OnboardRequest>,
) -> Result<(StatusCode, Json<OnboardResponse>), (StatusCode, Json<ErrorResponse>)> {
    let clean_samples: Vec<&str> = payload
        .sample_lines
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    if clean_samples.len() < 3 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Insufficient Samples".to_string(),
                code: 400,
                message: format!(
                    "Air-gapped parser synthesis requires at least 3 distinct sample lines (received {})",
                    clean_samples.len()
                ),
                block_id: None,
                leaf_index: None,
            }),
        ));
    }

    let (parser_def, report) =
        Onboarder::generate_parser(&payload.vendor, &payload.device_model, &clean_samples)
            .map_err(|e| {
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    Json(ErrorResponse {
                        error: "Synthesis Failed".to_string(),
                        code: 422,
                        message: format!("Failed to synthesize parser specification: {}", e),
                        block_id: None,
                        leaf_index: None,
                    }),
                )
            })?;

    // Destructive action check: confirm must be explicitly true
    if !payload.confirm {
        return Ok((
            StatusCode::OK,
            Json(OnboardResponse {
                status: "preview".to_string(),
                persisted: false,
                vendor: payload.vendor,
                device_model: payload.device_model,
                parser_definition: parser_def,
                validation_report: report,
                json_path: None,
                yaml_path: None,
                message: "Parser synthesized successfully (Preview mode: confirm=false, no files written)."
                    .to_string(),
            }),
        ));
    }

    // Persist parser to data/parsers/
    // Surface the cause here rather than letting it resurface as a misleading
    // "failed writing parser JSON" at the write below.
    std::fs::create_dir_all(&state.parsers_dir).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Disk Write Error".to_string(),
                code: 500,
                message: format!("Failed creating parsers directory: {}", e),
                block_id: None,
                leaf_index: None,
            }),
        )
    })?;
    let mut vendor_slug: String = payload
        .vendor
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    if vendor_slug.trim_matches('_').is_empty() {
        vendor_slug = "custom_vendor".to_string();
    }
    let json_file = format!("{}.json", vendor_slug);
    let yaml_file = format!("{}.yaml", vendor_slug);

    // Take the persistence lock BEFORE snapshotting: the snapshot, the two
    // renames, and any rollback are one transaction over this slug. Without it
    // two concurrent requests for the same vendor interleave and the loser's
    // rollback can delete the winner's published pair. Held across the `await`
    // on the registry below, so a parser is never left on disk unregistered.
    let _persist_guard = state.persist_lock.lock().await;

    let json_path = state.parsers_dir.join(&json_file);
    let yaml_path = state.parsers_dir.join(&yaml_file);

    let json_str = parser_def.to_json().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Serialization Error".to_string(),
                code: 500,
                message: format!("Failed serializing parser to JSON: {}", e),
                block_id: None,
                leaf_index: None,
            }),
        )
    })?;

    let yaml_str = parser_def.to_yaml().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Serialization Error".to_string(),
                code: 500,
                message: format!("Failed serializing parser to YAML: {}", e),
                block_id: None,
                leaf_index: None,
            }),
        )
    })?;

    // Persist the parser definition as a PAIR (JSON for the loader, YAML for
    // humans) — atomically. `publish_parser_pair` tmp-writes both payloads
    // then renames them over the targets, so readers never see a
    // half-published definition and a crash mid-write leaves whole files
    // behind, never truncated ones.
    let disk_err = |what: &str, e: std::io::Error| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Disk Write Error".to_string(),
                code: 500,
                message: format!("Failed writing parser {what} to disk: {e}"),
                block_id: None,
                leaf_index: None,
            }),
        )
    };
    publish_parser_pair(
        &state.parsers_dir,
        &json_file,
        &yaml_file,
        &json_str,
        &yaml_str,
    )
    .map_err(|e| disk_err("JSON+YAML pair", e))?;

    // Hot-load into active registry
    {
        let mut reg = state.registry.write().await;
        let _ = reg.register(parser_def.clone());
    }

    Ok((
        StatusCode::CREATED,
        Json(OnboardResponse {
            status: "hot_loaded".to_string(),
            persisted: true,
            vendor: payload.vendor,
            device_model: payload.device_model,
            parser_definition: parser_def,
            validation_report: report,
            json_path: Some(json_path.display().to_string()),
            yaml_path: Some(yaml_path.display().to_string()),
            message: "Parser hot-loaded into active memory and written to disk.".to_string(),
        }),
    ))
}

/// GET /system
pub async fn get_system(State(state): State<AppState>) -> Json<SystemResponse> {
    let uptime = state.start_time.elapsed().as_secs();

    let mut blocks_count = 0;
    if state.ledger_path.exists() {
        if let Ok(entries) = BatchAccumulator::load_ledger_entries(&state.ledger_path) {
            blocks_count = entries.len();
        }
    }

    let dynamic_count = if state.parsers_dir.exists() {
        std::fs::read_dir(&state.parsers_dir)
            .map(|e| {
                e.flatten()
                    .filter(|f| f.path().extension().and_then(|s| s.to_str()) == Some("json"))
                    .count()
            })
            .unwrap_or(0)
    } else {
        0
    };

    // Load benchmark scorecard if eval_report.json exists
    let benchmark_summary = if state.eval_report_path.exists() {
        std::fs::read_to_string(&state.eval_report_path)
            .ok()
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
    } else {
        None
    };

    Json(SystemResponse {
        service_name: "ULPF Air-Gapped Forensic Backend".to_string(),
        version: "0.1.0".to_string(),
        air_gapped: true,
        uptime_secs: uptime,
        batcher: BatcherConfigDisplay {
            max_batch_size: 1_000,
            max_batch_duration_ms: 2_000,
            storage_dir: state.parquet_dir.display().to_string(),
            ledger_path: state.ledger_path.display().to_string(),
            compression: "Snappy (Lossless Columnar Parquet)".to_string(),
        },
        ingest_queue_capacity: 50_000,
        ingest_queue_depth: 0,
        dynamic_parsers_loaded: dynamic_count,
        total_archived_blocks: blocks_count,
        benchmark_summary,
    })
}

/// POST /tamper/drill
/// Isolated adversary tamper drill.
/// Always clones target block to data/scratch/ and tampers ONLY the clone.
/// Never mutates real evidence.
pub async fn post_tamper_drill(
    State(state): State<AppState>,
    Json(payload): Json<TamperDrillRequest>,
) -> Result<Json<TamperDrillResponse>, (StatusCode, Json<ErrorResponse>)> {
    let filename = format!("block_{:05}.parquet", payload.block_id);
    let original_path = state.parquet_dir.join(&filename);

    if !original_path.exists() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Not Found".to_string(),
                code: 404,
                message: format!(
                    "Target block #{} does not exist at {}",
                    payload.block_id,
                    original_path.display()
                ),
                block_id: Some(payload.block_id),
                leaf_index: Some(payload.leaf_index),
            }),
        ));
    }

    let _ = std::fs::create_dir_all(&state.scratch_dir);
    let drill_filename = format!("tamper_drill_block_{:05}.parquet", payload.block_id);
    let drill_copy_path = state.scratch_dir.join(&drill_filename);

    // Destructive action check: confirm must be true to execute
    if !payload.confirm {
        return Ok(Json(TamperDrillResponse {
            status: "preview".to_string(),
            executed: false,
            target_block_id: payload.block_id,
            target_leaf_index: payload.leaf_index,
            spoofed_ip: payload.spoofed_ip,
            source_evidence_path: original_path.display().to_string(),
            scratch_drill_path: drill_copy_path.display().to_string(),
            original_evidence_unmodified: true,
            tamper_report: None,
            message: "Tamper Drill Plan: will clone evidence block to scratch directory and corrupt ONLY the copy. Pass 'confirm: true' to execute.".to_string(),
        }));
    }

    // Step 1: Clone target block to scratch
    std::fs::copy(&original_path, &drill_copy_path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Copy Failed".to_string(),
                code: 500,
                message: format!("Failed cloning evidence block to scratch directory: {}", e),
                block_id: Some(payload.block_id),
                leaf_index: Some(payload.leaf_index),
            }),
        )
    })?;

    // Step 2: Read records from the CLONE
    let mut records = read_parquet_file(&drill_copy_path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Read Error".to_string(),
                code: 500,
                message: format!("Failed reading scratch block clone: {}", e),
                block_id: Some(payload.block_id),
                leaf_index: Some(payload.leaf_index),
            }),
        )
    })?;

    if payload.leaf_index >= records.len() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Index Out of Bounds".to_string(),
                code: 400,
                message: format!(
                    "Leaf index {} exceeds clone record count {}",
                    payload.leaf_index,
                    records.len()
                ),
                block_id: Some(payload.block_id),
                leaf_index: Some(payload.leaf_index),
            }),
        ));
    }

    // Step 3: Inject spoofed IP into the CLONED record
    let original_raw = records[payload.leaf_index].raw_log.clone();
    let ip_regex = regex::Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap();
    let tampered_raw = if ip_regex.is_match(&original_raw) {
        ip_regex
            .replace(&original_raw, payload.spoofed_ip.as_str())
            .to_string()
    } else {
        format!("{} [TAMPER_DRILL_IP:{}]", original_raw, payload.spoofed_ip)
    };

    records[payload.leaf_index].raw_log = tampered_raw;

    // Step 4: Rewrite CLONED Parquet file
    write_records_to_parquet(&drill_copy_path, &records, ParquetCompression::Snappy).map_err(
        |e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Write Error".to_string(),
                    code: 500,
                    message: format!("Failed rewriting tampered scratch block: {}", e),
                    block_id: Some(payload.block_id),
                    leaf_index: Some(payload.leaf_index),
                }),
            )
        },
    )?;

    // Step 5: Verify CLONED block against real ledger
    let report = verify_block_with_ledger(&drill_copy_path, &state.ledger_path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Audit Failure".to_string(),
                code: 500,
                message: format!("Verification engine encountered unexpected error: {}", e),
                block_id: Some(payload.block_id),
                leaf_index: Some(payload.leaf_index),
            }),
        )
    })?;

    // Step 6: Append alert to feed
    {
        let mut alerts = state.alerts.write().await;
        alerts.insert(
            0,
            AlertItem {
                id: Uuid::now_v7().to_string(),
                alert_type: "tamper_alarm".to_string(),
                severity: AlertSeverity::Critical,
                timestamp: Utc::now().timestamp_millis(),
                title: format!("Tamper Drill Alarm: Block #{}", payload.block_id),
                details: format!(
                    "Adversarial drill detected spoofed IP {} at leaf {}. Merkle root mismatch on isolated clone.",
                    payload.spoofed_ip, payload.leaf_index
                ),
                block_id: Some(payload.block_id),
                leaf_index: Some(payload.leaf_index as u32),
            },
        );
    }

    Ok(Json(TamperDrillResponse {
        status: "tamper_detected".to_string(),
        executed: true,
        target_block_id: payload.block_id,
        target_leaf_index: payload.leaf_index,
        spoofed_ip: payload.spoofed_ip,
        source_evidence_path: original_path.display().to_string(),
        scratch_drill_path: drill_copy_path.display().to_string(),
        original_evidence_unmodified: true,
        tamper_report: Some(report),
        message: "Tamper Drill executed on cloned scratch copy. Original evidence remained 100% untouched. Red integrity alarm generated."
            .to_string(),
    }))
}

/// GET /export/bundle/:id
/// One-click courtroom evidence bundle export.
/// Returns a .tar.gz bundle with block parquet, ledger line, audit instructions, and checksums.
pub async fn get_export_bundle(
    AxumPath(block_id): AxumPath<u64>,
    State(state): State<AppState>,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let block_filename = format!("block_{:05}.parquet", block_id);
    let parquet_path = state.parquet_dir.join(&block_filename);

    if !parquet_path.exists() {
        return Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "Not Found".to_string(),
                code: 404,
                message: format!("Block Parquet file {} does not exist", block_filename),
                block_id: Some(block_id),
                leaf_index: None,
            }),
        ));
    }

    let parquet_bytes = std::fs::read(&parquet_path).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Read Error".to_string(),
                code: 500,
                message: format!("Failed reading Parquet bytes: {}", e),
                block_id: Some(block_id),
                leaf_index: None,
            }),
        )
    })?;

    // Extract ledger line
    let mut ledger_line = String::new();
    if state.ledger_path.exists() {
        if let Ok(file) = File::open(&state.ledger_path) {
            let reader = BufReader::new(file);
            for line in reader.lines().map_while(Result::ok) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                    if val.get("block_id").and_then(|v| v.as_u64()) == Some(block_id) {
                        ledger_line = line;
                        break;
                    }
                }
            }
        }
    }

    let mut parquet_hasher = Sha256::new();
    parquet_hasher.update(&parquet_bytes);
    let parquet_sha = hex::encode(parquet_hasher.finalize());

    let mut ledger_hasher = Sha256::new();
    ledger_hasher.update(ledger_line.as_bytes());
    let ledger_sha = hex::encode(ledger_hasher.finalize());

    let readme = format!(
        "================================================================================\n\
         ULPF COURTROOM EVIDENCE BUNDLE\n\
         Block ID: #{:05}\n\
         Timestamp: {}\n\
         Standard: RFC 6962 Certificate Transparency Standard / OCSF 1.3\n\
         ================================================================================\n\n\
         CONTENTS:\n\
         1. {} (Columnar Parquet log archive with lossless raw logs, SHA-256 digests, and OCSF 1.3 records)\n\
         2. ledger_entry.json (Immutable append-only Merkle ledger entry)\n\
         3. SHA256SUMS (Cryptographic manifest of all bundle artifacts)\n\n\
         VERIFICATION INSTRUCTIONS (Air-Gapped):\n\
         To cryptographically audit this evidence block using the official ULPF verifier binary:\n\n\
           ulpf verify --file {} --ledger ledger_entry.json\n\n\
         A green [PASS] indicates 100% cryptographic integrity: zero modified bytes, zero injected records,\n\
         and exact Merkle root mathematical alignment.\n",
        block_id,
        Utc::now().to_rfc3339(),
        block_filename,
        block_filename
    );

    let sha256sums = format!(
        "{}  {}\n{}  ledger_entry.json\n",
        parquet_sha, block_filename, ledger_sha
    );

    // Build tar.gz in memory
    let mut enc = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut tar = Builder::new(&mut enc);

        // Append README
        let mut header = tar::Header::new_gnu();
        header.set_path("README.txt").unwrap();
        header.set_size(readme.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, readme.as_bytes()).unwrap();

        // Append Parquet
        let mut header = tar::Header::new_gnu();
        header.set_path(&block_filename).unwrap();
        header.set_size(parquet_bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, &parquet_bytes[..]).unwrap();

        // Append Ledger Entry
        let mut header = tar::Header::new_gnu();
        header.set_path("ledger_entry.json").unwrap();
        header.set_size(ledger_line.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, ledger_line.as_bytes()).unwrap();

        // Append Checksums
        let mut header = tar::Header::new_gnu();
        header.set_path("SHA256SUMS").unwrap();
        header.set_size(sha256sums.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        tar.append(&header, sha256sums.as_bytes()).unwrap();

        tar.finish().unwrap();
    }

    let bundle_bytes = enc.finish().map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Compression Error".to_string(),
                code: 500,
                message: format!("Failed compressing evidence bundle: {}", e),
                block_id: Some(block_id),
                leaf_index: None,
            }),
        )
    })?;

    let download_filename = format!("ulpf_evidence_block_{:05}.tar.gz", block_id);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/gzip"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        HeaderValue::from_str(&format!("attachment; filename=\"{}\"", download_filename)).unwrap(),
    );

    Ok((headers, bundle_bytes).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `GET /parsers` must not report a parser that cannot work as `active`.
    ///
    /// Two failure modes used to be invisible on this endpoint. A file that
    /// failed to deserialize was skipped entirely, so it simply did not appear
    /// — indistinguishable from never having been onboarded. And a definition
    /// whose `regex_pattern` does not compile was listed `active`, even though
    /// it can never match an event. Both are reported now, and each is
    /// distinguishable, because an operator reading this endpoint has no other
    /// way to tell a working parser from a dead one.
    #[tokio::test]
    async fn get_parsers_reports_invalid_and_malformed_instead_of_hiding_them() {
        let dir = scratch_dir("parsers-status");

        let good = ParserDefinition {
            vendor: "goodco".into(),
            device_model: "ok".into(),
            regex_pattern: r"^src=(?P<src_ip>[0-9.]+)$".to_string(),
            action_mappings: HashMap::new(),
            sample_logs: vec![],
            confidence_score: 1.0,
            created_at: 0,
            regex_cache: std::sync::Arc::new(std::sync::OnceLock::new()),
        };
        std::fs::write(dir.join("good.json"), good.to_json().unwrap()).unwrap();

        // Loads fine, but the pattern cannot compile.
        std::fs::write(
            dir.join("broken.json"),
            br#"{"vendor":"brokenco","device_model":"bx","regex_pattern":"^(?P<src_ip>[unclosed","action_mappings":{},"sample_logs":[],"confidence_score":1.0,"created_at":0}"#,
        )
        .unwrap();

        // Does not deserialize at all.
        std::fs::write(dir.join("malformed.json"), b"{ not json").unwrap();

        // Not a parser file; must stay out of the listing entirely.
        std::fs::write(dir.join("notes.txt"), b"hello").unwrap();

        let items = get_parsers(State(AppState::new(
            dir.clone(),
            dir.join("ledger.jsonl"),
            dir.clone(),
            dir.join("eval.md"),
        )))
        .await
        .0;
        let dynamic: Vec<&ParserItem> = items
            .iter()
            .filter(|i| i.parser_type == "dynamic_onboarded")
            .collect();

        let by_status = |s: &str| {
            dynamic
                .iter()
                .find(|i| i.status == s)
                .unwrap_or_else(|| panic!("no parser reported status {s:?} in {dynamic:?}"))
        };

        assert_eq!(by_status("active").vendor, "goodco");
        assert_eq!(by_status("invalid").vendor, "brokenco");
        assert_eq!(by_status("malformed").vendor, "<malformed>");

        // Exactly three: the .txt must not be listed, and nothing was skipped
        // into invisibility.
        assert_eq!(
            dynamic.len(),
            3,
            "expected good + broken + malformed, got {dynamic:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Fresh temp dir per test (pid-tagged): publish tests must not share
    /// state, and must not touch the repo's real `data/parsers`.
    fn scratch_dir(case: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ulpf-publish-test-{}-{}-{}",
            case,
            std::process::id(),
            PUBLISH_TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scratch dir must be creatable");
        dir
    }

    /// No temp file may survive a publish. A leftover `*.tmp-*` is a staged
    /// definition that was never published, and a `*.rollback-tmp-*` is a
    /// staged restore that never landed — both are debris, so the check covers
    /// both name shapes. `publish_parser_pair` never scans the directory, so
    /// this is purely an assertion that the cleanup paths ran.
    fn assert_no_tmps(dir: &std::path::Path) {
        let leftovers: Vec<_> = std::fs::read_dir(dir)
            .expect("scratch dir must be listable")
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("tmp-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "temp files left behind after publish: {leftovers:?}"
        );
    }

    #[test]
    fn test_publish_pair_writes_both_then_renames() {
        let dir = scratch_dir("happy");
        publish_parser_pair(&dir, "fw.json", "fw.yaml", r#"{"a":1}"#, "a: 1\n")
            .expect("fresh publish must succeed");
        assert_eq!(
            std::fs::read_to_string(dir.join("fw.json")).unwrap(),
            r#"{"a":1}"#
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("fw.yaml")).unwrap(),
            "a: 1\n"
        );
        assert_no_tmps(&dir);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Crash-window proxy: block the YAML rename (a directory where the file
    /// must go — fails even as root, unlike permission bits) and assert the
    /// JSON half is NOT left behind with new content.
    #[test]
    fn test_publish_pair_failure_leaves_no_half_pair() {
        let dir = scratch_dir("half");
        std::fs::create_dir(dir.join("fw.yaml")).expect("blocker dir must be creatable");

        let err = publish_parser_pair(&dir, "fw.json", "fw.yaml", "NEW-JSON", "NEW-YAML")
            .expect_err("YAML rename onto a directory must fail");
        let _ = err;

        assert!(
            !dir.join("fw.json").exists(),
            "failed publish must not leave the JSON half behind"
        );
        // The blocker itself is untouched — rollback removes files, never dirs.
        assert!(dir.join("fw.yaml").is_dir());
        assert_no_tmps(&dir);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Same failure, but a parser was already published: the JSON target
    /// must be rolled back to its PRIOR contents, not deleted, and the YAML
    /// prior must be intact.
    #[test]
    fn test_publish_pair_failure_restores_prior() {
        let dir = scratch_dir("rollback");
        std::fs::write(dir.join("fw.json"), "OLD-JSON").unwrap();
        std::fs::write(dir.join("fw.yaml"), "OLD-YAML").unwrap();
        // Re-publish over the pair first: proves overwrite works mid-test.
        publish_parser_pair(&dir, "fw.json", "fw.yaml", "MID-JSON", "MID-YAML").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("fw.json")).unwrap(),
            "MID-JSON"
        );

        // Now block the YAML target and re-publish: JSON rename succeeds,
        // YAML rename fails, JSON must roll back to MID-JSON.
        std::fs::remove_file(dir.join("fw.yaml")).unwrap();
        std::fs::create_dir(dir.join("fw.yaml")).unwrap();
        publish_parser_pair(&dir, "fw.json", "fw.yaml", "NEW-JSON", "NEW-YAML")
            .expect_err("blocked YAML rename must fail");
        assert_eq!(
            std::fs::read_to_string(dir.join("fw.json")).unwrap(),
            "MID-JSON",
            "JSON half must roll back to prior contents, not keep NEW-JSON"
        );
        assert!(dir.join("fw.yaml").is_dir());
        assert_no_tmps(&dir);

        // Unblock and prove the pair still publishes cleanly afterwards.
        std::fs::remove_dir(dir.join("fw.yaml")).unwrap();
        publish_parser_pair(&dir, "fw.json", "fw.yaml", "NEW-JSON", "NEW-YAML").unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("fw.json")).unwrap(),
            "NEW-JSON"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("fw.yaml")).unwrap(),
            "NEW-YAML"
        );
        assert_no_tmps(&dir);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A rollback that completes cleanly must report ONLY the publish failure.
    ///
    /// The half that renamed successfully no longer has a temp file, so
    /// `remove_file` on it returns `NotFound` — which is the expected case, not
    /// a rollback problem. Counting it made every clean rollback report itself
    /// as incomplete, which would train operators to ignore that signal.
    #[test]
    fn test_publish_pair_clean_rollback_reports_only_publish_failure() {
        let dir = scratch_dir("cleanrollback");
        std::fs::write(dir.join("fw.json"), "OLD-JSON").unwrap();
        std::fs::create_dir(dir.join("fw.yaml")).expect("blocker dir must be creatable");

        let err = publish_parser_pair(&dir, "fw.json", "fw.yaml", "NEW-JSON", "NEW-YAML")
            .expect_err("blocked YAML rename must fail");
        let msg = err.to_string();
        assert!(
            !msg.contains("rollback was incomplete"),
            "a rollback that restored cleanly must NOT claim incompleteness: {msg}"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("fw.json")).unwrap(),
            "OLD-JSON",
            "prior contents must be back"
        );
        assert_no_tmps(&dir);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An UNREADABLE prior file must never be deleted by a rollback.
    ///
    /// The snapshot used to be `fs::read(..).ok()`, which collapses "no file
    /// there" and "the file is there but I could not read it" into the same
    /// `None` — and the rollback deletes on `None`. So a parser that existed
    /// but was unreadable at snapshot time (bad ownership after a restore from
    /// another host, a transient I/O error, a file that is not a regular file)
    /// would have been DELETED when the publish failed, not restored. Losing a
    /// working parser because an unrelated write failed is the worst possible
    /// outcome of a rollback.
    ///
    /// A unix socket file is the deterministic stand-in for "exists, will not
    /// read": `read` fails `ENXIO`, which is not `NotFound`, while a rename over
    /// it succeeds, so the publish really does proceed and really does fail
    /// afterwards. A `chmod 000` file would be simpler but is unreliable — as
    /// root it is still readable, and this suite is documented to run as root.
    #[cfg(unix)]
    #[test]
    fn test_publish_pair_never_deletes_an_unreadable_prior_file() {
        use std::os::unix::net::UnixListener;

        let dir = scratch_dir("unreadable-prior");
        // Prior "parser" that cannot be read...
        let json_path = dir.join("fw.json");
        let listener = UnixListener::bind(&json_path).expect("socket path must be bindable");
        // ...and a YAML target that cannot be renamed over, to force the
        // failure that triggers the rollback.
        std::fs::create_dir(dir.join("fw.yaml")).expect("blocker dir must be creatable");

        let err = publish_parser_pair(&dir, "fw.json", "fw.yaml", "NEW-JSON", "NEW-YAML")
            .expect_err("blocked YAML rename must fail");
        let msg = err.to_string();

        assert!(
            msg.contains("rollback was incomplete"),
            "an unrestorable prior file must be reported, not swallowed: {msg}"
        );
        assert!(
            msg.contains("could not read the prior file"),
            "the error must name the reason: {msg}"
        );

        // The file must still be there, holding the new content. This is the
        // whole point: a rollback that deleted an unreadable prior file would
        // leave the path GONE, taking a parser definition with it. Leaving the
        // new content in place loses nothing that was readable, and the
        // incompleteness is reported above so an operator can reconcile it.
        assert!(
            json_path.exists(),
            "the prior file was DELETED instead of left in place"
        );
        assert_eq!(
            std::fs::read_to_string(&json_path).unwrap(),
            "NEW-JSON",
            "the new content must be intact, not truncated or removed"
        );

        drop(listener);
        std::fs::remove_file(&json_path).ok();
        assert_no_tmps(&dir);
        std::fs::remove_dir_all(&dir).ok();
    }
}
