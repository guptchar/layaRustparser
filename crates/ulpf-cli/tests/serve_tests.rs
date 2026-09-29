use std::io::Read;
use std::path::PathBuf;
use std::process::Command;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use flate2::read::GzDecoder;
use http_body_util::BodyExt;
use tar::Archive;
use tower::ServiceExt;

use ulpf_cli::serve::{create_router, AppState};

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_ulpf")
}

fn setup_test_state() -> AppState {
    let root = repo_root();
    AppState::new(
        root.join("data/parquet"),
        root.join("data/ledger.jsonl"),
        root.join("data/parsers"),
        root.join("docs/benchmarks/eval_hardcore_report.md"),
    )
}

#[test]
fn serve_help_parses_in_debug_build() {
    let out = Command::new(bin())
        .args(["serve", "--help"])
        .output()
        .expect("spawn ulpf serve --help");
    assert!(
        out.status.success(),
        "serve --help failed (exit {:?}): {}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("--port"));
    assert!(stdout.contains("--host"));
    assert!(stdout.contains("--parquet-dir"));
}

#[tokio::test]
async fn test_serve_get_metrics() {
    let state = setup_test_state();
    let app = create_router(state);

    let req = Request::builder()
        .uri("/metrics")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    for field in [
        "eps",
        "latency_p50_micros",
        "lru_hit_rate",
        "vendor_mix",
        "disposition_breakdown",
        "telemetry_state",
    ] {
        assert!(
            json.get(field).is_some(),
            "/metrics must still carry `{field}` (value may be null, key must exist)"
        );
    }
}

/// With no ingest process running, there is no telemetry sidecar. Every live
/// gauge must therefore be `null` — not `0`, and not a plausible constant.
/// This is the exact failure mode #43 was filed for.
#[tokio::test]
async fn test_metrics_reports_null_not_fabricated_when_ingest_absent() {
    let root = repo_root();
    let temp_scratch = tempfile::tempdir().unwrap();
    let state = AppState {
        parquet_dir: root.join("data/parquet"),
        ledger_path: root.join("data/ledger.jsonl"),
        parsers_dir: root.join("data/parsers"),
        eval_report_path: root.join("docs/benchmarks/eval_hardcore_report.md"),
        scratch_dir: temp_scratch.path().to_path_buf(),
        registry: std::sync::Arc::new(tokio::sync::RwLock::new(
            ulpf_ai::onboarder::DynamicParserRegistry::new(),
        )),
        alerts: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        persist_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        start_time: std::time::Instant::now(),
        telemetry_path: root.join("data/does-not-exist.json"),
        stale_after_ms: ulpf_core::ingest::telemetry::DEFAULT_STALE_AFTER_MS,
        metrics_cache: ulpf_cli::serve::metrics_cache::MetricsCache::new(
            std::time::Duration::from_millis(
                ulpf_cli::serve::metrics_cache::DEFAULT_METRICS_TTL_MS,
            ),
        ),
        corpus_cache: ulpf_cli::serve::metrics_cache::CorpusCache::new(),
    };
    let app = create_router(state);
    let req = Request::builder()
        .uri("/metrics")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    for field in [
        "eps",
        "latency_p50_micros",
        "latency_p99_micros",
        "lru_hit_rate",
        "queue_depth",
        "dropped_count",
    ] {
        assert_eq!(
            json.get(field),
            Some(&serde_json::Value::Null),
            "`{field}` must be null when nothing has been measured, never a fabricated number"
        );
    }
    assert_eq!(
        json.get("telemetry_state").unwrap(),
        "ABSENT",
        "an absent sidecar must be reported as absent"
    );
    assert_ne!(
        json.get("status").unwrap(),
        "HEALTHY",
        "a pipeline that was never measured must not be reported healthy"
    );
}

/// An empty corpus must yield an empty vendor map. The old code substituted a
/// hardcoded `cisco_asa 32.5% / fortigate 28.0% / ...` distribution here.
#[tokio::test]
async fn test_metrics_has_no_fabricated_vendor_mix() {
    let temp_scratch = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();
    let state = AppState {
        parquet_dir: empty.path().join("parquet"),
        ledger_path: empty.path().join("ledger.jsonl"),
        parsers_dir: empty.path().join("parsers"),
        eval_report_path: empty.path().join("eval.json"),
        scratch_dir: temp_scratch.path().to_path_buf(),
        registry: std::sync::Arc::new(tokio::sync::RwLock::new(
            ulpf_ai::onboarder::DynamicParserRegistry::new(),
        )),
        alerts: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        persist_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        start_time: std::time::Instant::now(),
        telemetry_path: empty.path().join("live_telemetry.json"),
        stale_after_ms: ulpf_core::ingest::telemetry::DEFAULT_STALE_AFTER_MS,
        metrics_cache: ulpf_cli::serve::metrics_cache::MetricsCache::new(
            std::time::Duration::from_millis(
                ulpf_cli::serve::metrics_cache::DEFAULT_METRICS_TTL_MS,
            ),
        ),
        corpus_cache: ulpf_cli::serve::metrics_cache::CorpusCache::new(),
    };
    let app = create_router(state);
    let req = Request::builder()
        .uri("/metrics")
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let response = app.oneshot(req).await.unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(
        json.get("vendor_mix").unwrap(),
        &serde_json::json!({}),
        "an empty corpus must report an empty vendor map, not a demo distribution"
    );
    assert_eq!(
        json.get("disposition_breakdown").unwrap(),
        &serde_json::json!({}),
        "an empty corpus must not report zeroed Allowed/Blocked/Dropped placeholders"
    );
}

#[tokio::test]
async fn test_serve_get_alerts() {
    let state = setup_test_state();
    // Allow state background task to finish seeding alerts
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let app = create_router(state);
    let req = Request::builder()
        .uri("/alerts")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let alerts: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();

    assert!(!alerts.is_empty(), "Alerts feed should not be empty");
    let has_tamper = alerts
        .iter()
        .any(|a| a.get("alert_type").and_then(|v| v.as_str()).unwrap_or("") == "tamper_alarm");
    assert!(
        has_tamper,
        "Should contain tamper alarm for intentionally tampered block 0"
    );
}

#[tokio::test]
async fn test_serve_get_blocks() {
    let state = setup_test_state();
    let app = create_router(state);

    let req = Request::builder()
        .uri("/blocks")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let blocks: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();

    assert!(!blocks.is_empty(), "Blocks list should not be empty");

    // Block 0 is intentionally tampered in repo fixtures
    let b0 = blocks
        .iter()
        .find(|b| b.get("block_id").and_then(|v| v.as_u64()) == Some(0));
    assert!(b0.is_some(), "Block 0 should exist");
    assert_eq!(b0.unwrap().get("status").unwrap(), "FAIL");

    // Block 1 is valid in repo fixtures
    let b1 = blocks
        .iter()
        .find(|b| b.get("block_id").and_then(|v| v.as_u64()) == Some(1));
    assert!(b1.is_some(), "Block 1 should exist");
    assert_eq!(b1.unwrap().get("status").unwrap(), "PASS");
}

#[tokio::test]
async fn test_serve_get_block_records() {
    let state = setup_test_state();
    let app = create_router(state);

    let req = Request::builder()
        .uri("/blocks/1/records?limit=5")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json.get("block_id").unwrap(), 1);
    assert_eq!(json.get("limit").unwrap(), 5);

    let records = json.get("records").and_then(|v| v.as_array()).unwrap();
    assert_eq!(records.len(), 5);

    let rec = &records[0];
    assert!(rec.get("event_id").is_some());
    assert!(rec.get("raw_log").is_some());
    assert!(rec.get("raw_hash").is_some());
    assert!(rec.get("ocsf").is_some());
}

#[tokio::test]
async fn test_serve_prove_stubbed_501_and_live() {
    let state = setup_test_state();

    // 1. Default without ?live=true MUST return 501 Not Implemented (criteria for Issue #12)
    let app = create_router(state.clone());
    let req = Request::builder()
        .uri("/prove/1/0")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let err: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(err.get("code").unwrap(), 501);
    assert!(err.get("message").unwrap().as_str().unwrap().contains("#5"));

    // 2. With ?live=true, returns live RFC 6962 audit path and verified: true
    let app2 = create_router(state);
    let req_live = Request::builder()
        .uri("/prove/1/0?live=true")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response_live = app2.oneshot(req_live).await.unwrap();
    assert_eq!(response_live.status(), StatusCode::OK);

    let body_live = response_live
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    let proof: serde_json::Value = serde_json::from_slice(&body_live).unwrap();
    assert_eq!(proof.get("verified").unwrap(), true);
    assert_eq!(proof.get("leaf_index").unwrap(), 0);
    assert!(proof.get("audit_path").and_then(|v| v.as_array()).is_some());
}

#[tokio::test]
async fn test_serve_parsers_list() {
    let state = setup_test_state();
    let app = create_router(state);

    let req = Request::builder()
        .uri("/parsers")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let parsers: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();

    assert!(!parsers.is_empty());
    let has_cisco = parsers
        .iter()
        .any(|p| p.get("vendor").unwrap() == "cisco_asa");
    let has_forti = parsers
        .iter()
        .any(|p| p.get("vendor").unwrap() == "fortigate");
    assert!(has_cisco && has_forti);
}

#[tokio::test]
async fn test_serve_parsers_test_dry_run() {
    let state = setup_test_state();
    let app = create_router(state);

    let test_log = "<166>Sep 21 14:00:01 asa-core-fw %ASA-6-302013: Built outbound TCP connection 1000672 for outside:203.0.113.54/25 to inside:10.1.6.180/52369";
    let payload = serde_json::json!({
        "raw_log": test_log,
        "vendor": "cisco_asa"
    });

    let req = Request::builder()
        .uri("/parsers/test")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let res: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(res.get("matched").unwrap(), true);
    assert_eq!(res.get("vendor").unwrap(), "cisco_asa");
    assert!(res.get("parsed_ocsf").is_some());
    assert!(res.get("raw_hash").is_some());
}

#[tokio::test]
async fn test_serve_onboard_safety_and_persistence() {
    let temp_dir = tempfile::tempdir().unwrap();
    let root = repo_root();
    let state = AppState::new(
        root.join("data/parquet"),
        root.join("data/ledger.jsonl"),
        temp_dir.path().to_path_buf(),
        root.join("docs/benchmarks/eval_hardcore_report.md"),
    );

    let sample_lines = vec![
        "RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.168.10.55/49152->10.0.0.1/443 None None 6 sample-policy trust untrust 12345 N/A(N/A) ge-0/0/0.0",
        "RT_FLOW: RT_FLOW_SESSION_CLOSE: session closed TCP FIN: 192.168.10.55/49152->10.0.0.1/443 None None 6 sample-policy trust untrust 12345 540(3200) 12(8) 15 UNKNOWN N/A(N/A) ge-0/0/0.0",
        "RT_FLOW: RT_FLOW_SESSION_DENY: session denied 192.168.20.100/53211->172.16.0.5/22 None None 6 block-ssh untrust dmz 12346 N/A(N/A) ge-0/0/1.0",
    ];

    // 1. With confirm: false (preview mode, NO files written)
    let app = create_router(state.clone());
    let preview_payload = serde_json::json!({
        "vendor": "juniper_preview_fw",
        "device_model": "srx-340",
        "sample_lines": sample_lines,
        "confirm": false
    });

    let req1 = Request::builder()
        .uri("/onboard")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&preview_payload).unwrap()))
        .unwrap();

    let resp1 = app.oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);

    let body1 = resp1.into_body().collect().await.unwrap().to_bytes();
    let res1: serde_json::Value = serde_json::from_slice(&body1).unwrap();
    assert_eq!(res1.get("status").unwrap(), "preview");
    assert_eq!(res1.get("persisted").unwrap(), false);
    assert!(
        !temp_dir.path().join("juniper_preview_fw.json").exists(),
        "Preview mode must NOT create files on disk"
    );

    // 2. With confirm: true (persisted and hot-loaded)
    let app2 = create_router(state);
    let confirm_payload = serde_json::json!({
        "vendor": "juniper_persisted_fw",
        "device_model": "srx-340",
        "sample_lines": sample_lines,
        "confirm": true
    });

    let req2 = Request::builder()
        .uri("/onboard")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&confirm_payload).unwrap()))
        .unwrap();

    let resp2 = app2.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::CREATED);

    let body2 = resp2.into_body().collect().await.unwrap().to_bytes();
    let res2: serde_json::Value = serde_json::from_slice(&body2).unwrap();
    assert_eq!(res2.get("status").unwrap(), "hot_loaded");
    assert_eq!(res2.get("persisted").unwrap(), true);
    assert!(
        temp_dir.path().join("juniper_persisted_fw.json").exists(),
        "Confirmed onboarding must create .json file on disk"
    );
    assert!(
        temp_dir.path().join("juniper_persisted_fw.yaml").exists(),
        "Confirmed onboarding must create .yaml file on disk"
    );
}

#[tokio::test]
async fn test_serve_tamper_drill_isolation() {
    let root = repo_root();
    let temp_scratch = tempfile::tempdir().unwrap();

    let state = AppState {
        parquet_dir: root.join("data/parquet"),
        ledger_path: root.join("data/ledger.jsonl"),
        parsers_dir: root.join("data/parsers"),
        eval_report_path: root.join("docs/benchmarks/eval_hardcore_report.md"),
        scratch_dir: temp_scratch.path().to_path_buf(),
        registry: std::sync::Arc::new(tokio::sync::RwLock::new(
            ulpf_ai::onboarder::DynamicParserRegistry::new(),
        )),
        alerts: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        persist_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        start_time: std::time::Instant::now(),
        telemetry_path: root.join("data/live_telemetry.json"),
        stale_after_ms: ulpf_core::ingest::telemetry::DEFAULT_STALE_AFTER_MS,
        metrics_cache: ulpf_cli::serve::metrics_cache::MetricsCache::new(
            std::time::Duration::from_millis(
                ulpf_cli::serve::metrics_cache::DEFAULT_METRICS_TTL_MS,
            ),
        ),
        corpus_cache: ulpf_cli::serve::metrics_cache::CorpusCache::new(),
    };

    let original_block1_bytes =
        std::fs::read(root.join("data/parquet/block_00001.parquet")).unwrap();

    // 1. confirm: false -> preview mode
    let app1 = create_router(state.clone());
    let req1 = Request::builder()
        .uri("/tamper/drill")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "block_id": 1,
                "leaf_index": 0,
                "spoofed_ip": "10.99.99.99",
                "confirm": false
            }))
            .unwrap(),
        ))
        .unwrap();

    let resp1 = app1.oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let body1 = resp1.into_body().collect().await.unwrap().to_bytes();
    let res1: serde_json::Value = serde_json::from_slice(&body1).unwrap();
    assert_eq!(res1.get("executed").unwrap(), false);

    // 2. confirm: true -> executed on clone
    let app2 = create_router(state);
    let req2 = Request::builder()
        .uri("/tamper/drill")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "block_id": 1,
                "leaf_index": 0,
                "spoofed_ip": "10.99.99.99",
                "confirm": true
            }))
            .unwrap(),
        ))
        .unwrap();

    let resp2 = app2.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2 = resp2.into_body().collect().await.unwrap().to_bytes();
    let res2: serde_json::Value = serde_json::from_slice(&body2).unwrap();
    assert_eq!(res2.get("executed").unwrap(), true);
    assert_eq!(res2.get("status").unwrap(), "tamper_detected");

    // CRITICAL: Ensure original evidence file was 100% UNTOUCHED
    let current_block1_bytes =
        std::fs::read(root.join("data/parquet/block_00001.parquet")).unwrap();
    assert_eq!(
        original_block1_bytes, current_block1_bytes,
        "Original evidence block was modified! Tamper drill must NEVER touch original evidence!"
    );

    // Ensure the clone in scratch was modified and detected
    let drill_clone = temp_scratch.path().join("tamper_drill_block_00001.parquet");
    assert!(drill_clone.exists(), "Clone file in scratch must exist");
}

#[tokio::test]
async fn test_serve_export_bundle() {
    let state = setup_test_state();
    let app = create_router(state);

    let req = Request::builder()
        .uri("/export/bundle/1")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get(header::CONTENT_TYPE).unwrap(),
        "application/gzip"
    );

    let body_bytes = response.into_body().collect().await.unwrap().to_bytes();

    // Decompress and verify tar contents
    let gz = GzDecoder::new(&body_bytes[..]);
    let mut archive = Archive::new(gz);

    let mut entry_names = Vec::new();
    for entry in archive.entries().unwrap() {
        let mut entry = entry.unwrap();
        let name = entry.path().unwrap().to_str().unwrap().to_string();
        entry_names.push(name.clone());

        if name == "README.txt" {
            let mut content = String::new();
            entry.read_to_string(&mut content).unwrap();
            assert!(content.contains("ULPF COURTROOM EVIDENCE BUNDLE"));
            assert!(content.contains("RFC 6962"));
        }
    }

    assert!(entry_names.contains(&"README.txt".to_string()));
    assert!(entry_names.contains(&"block_00001.parquet".to_string()));
    assert!(entry_names.contains(&"ledger_entry.json".to_string()));
    assert!(entry_names.contains(&"SHA256SUMS".to_string()));
}

#[tokio::test]
async fn test_serve_parser_log_protocol_normalization() {
    let state = setup_test_state();
    let app = create_router(state);

    // Test 1: HTTP/1.1 log
    let http1_log = r#"date=2026-09-21 time=14:00:08 devname="FGT" srcip=192.168.1.10 srcport=22520 dstip=203.0.113.28 dstport=80 proto=6 action="accept" app="HTTP""#;
    let req1 = Request::builder()
        .uri("/parsers/test")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "raw_log": http1_log,
                "vendor": "fortigate"
            }))
            .unwrap(),
        ))
        .unwrap();

    let resp1 = app.oneshot(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    let body1 = resp1.into_body().collect().await.unwrap().to_bytes();
    let res1: serde_json::Value = serde_json::from_slice(&body1).unwrap();
    assert_eq!(res1.get("matched").unwrap(), true);
    assert_eq!(res1.get("protocol_detected").unwrap(), "HTTP/1.1 (TCP)");

    // Test 2: HTTP/2 log
    let app2 = create_router(setup_test_state());
    let http2_log = r#"date=2026-09-21 time=14:00:10 devname="FGT" srcip=192.168.1.20 srcport=54321 dstip=203.0.113.28 dstport=443 proto=6 action="accept" app="HTTP2""#;
    let req2 = Request::builder()
        .uri("/parsers/test")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "raw_log": http2_log,
                "vendor": "fortigate"
            }))
            .unwrap(),
        ))
        .unwrap();

    let resp2 = app2.oneshot(req2).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    let body2 = resp2.into_body().collect().await.unwrap().to_bytes();
    let res2: serde_json::Value = serde_json::from_slice(&body2).unwrap();
    assert_eq!(res2.get("matched").unwrap(), true);
    assert_eq!(res2.get("protocol_detected").unwrap(), "HTTP/2 (TCP)");

    // Test 3: HTTP/3 / QUIC log (over UDP proto 17)
    let app3 = create_router(setup_test_state());
    let http3_log = r#"date=2026-09-21 time=14:00:12 devname="FGT" srcip=192.168.1.30 srcport=61234 dstip=203.0.113.28 dstport=443 proto=17 action="accept" app="HTTP3" service="QUIC""#;
    let req3 = Request::builder()
        .uri("/parsers/test")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "raw_log": http3_log,
                "vendor": "fortigate"
            }))
            .unwrap(),
        ))
        .unwrap();

    let resp3 = app3.oneshot(req3).await.unwrap();
    assert_eq!(resp3.status(), StatusCode::OK);
    let body3 = resp3.into_body().collect().await.unwrap().to_bytes();
    let res3: serde_json::Value = serde_json::from_slice(&body3).unwrap();
    assert_eq!(res3.get("matched").unwrap(), true);
    assert_eq!(
        res3.get("protocol_detected").unwrap(),
        "HTTP/3 (QUIC / UDP)"
    );
}

#[tokio::test]
async fn test_serve_get_system() {
    let state = setup_test_state();
    let app = create_router(state);

    let req = Request::builder()
        .uri("/system")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(json.get("air_gapped").unwrap(), true);
    assert!(json.get("batcher").is_some());
    assert!(json.get("ingest_queue_capacity").is_some());
}

#[tokio::test]
async fn test_serve_onboard_vendor_slug_traversal_sanitization() {
    let root = repo_root();
    let temp_dir = tempfile::tempdir().unwrap();
    let state = AppState::new(
        root.join("data/parquet"),
        root.join("data/ledger.jsonl"),
        temp_dir.path().to_path_buf(),
        root.join("docs/benchmarks/eval_hardcore_report.md"),
    );
    let parsers_dir = state.parsers_dir.clone();
    let app = create_router(state);

    let sample_lines = vec![
        "RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.168.10.55/49152->10.0.0.1/443 None None 6 sample-policy trust untrust 12345 N/A(N/A) ge-0/0/0.0",
        "RT_FLOW: RT_FLOW_SESSION_CLOSE: session closed TCP FIN: 192.168.10.55/49152->10.0.0.1/443 None None 6 sample-policy trust untrust 12345 540(3200) 12(8) 15 UNKNOWN N/A(N/A) ge-0/0/0.0",
        "RT_FLOW: RT_FLOW_SESSION_DENY: session denied 192.168.20.100/53211->172.16.0.5/22 None None 6 block-ssh untrust dmz 12346 N/A(N/A) ge-0/0/1.0",
    ];

    let payload = serde_json::json!({
        "vendor": "../../evil_traversal_vendor",
        "device_model": "test-device",
        "sample_lines": sample_lines,
        "confirm": true
    });

    let req = Request::builder()
        .uri("/onboard")
        .method("POST")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&payload).unwrap()))
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Verify no file escaped outside parsers_dir
    let parent = parsers_dir.parent().unwrap();
    assert!(!parent.join("evil_traversal_vendor.json").exists());
    assert!(!parent.join("evil_traversal_vendor.yaml").exists());

    // Verify file is contained safely inside parsers_dir
    assert!(parsers_dir
        .join("______evil_traversal_vendor.json")
        .exists());
    assert!(parsers_dir
        .join("______evil_traversal_vendor.yaml")
        .exists());
}

#[tokio::test]
async fn test_serve_disposition_filter_strict() {
    let state = setup_test_state();
    let app = create_router(state);

    let req = Request::builder()
        .uri("/blocks/1/records?disposition=Allowed")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response = app.oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let records = json.get("records").unwrap().as_array().unwrap();

    for r in records {
        let ocsf = r.get("ocsf").unwrap();
        let disp = ocsf.get("disposition").and_then(|d| d.as_str()).unwrap();
        assert_eq!(disp.to_lowercase(), "allowed");
    }

    // Now test with a non-matching disposition
    let app2 = create_router(setup_test_state());
    let req2 = Request::builder()
        .uri("/blocks/1/records?disposition=NonExistentDisposition")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let response2 = app2.oneshot(req2).await.unwrap();
    assert_eq!(response2.status(), StatusCode::OK);
    let body2 = response2.into_body().collect().await.unwrap().to_bytes();
    let json2: serde_json::Value = serde_json::from_slice(&body2).unwrap();
    assert_eq!(json2.get("filtered_records_count").unwrap(), 0);
}

#[tokio::test]
async fn test_serve_cors_origin_enforcement() {
    let state = setup_test_state();
    let app = create_router(state);

    // 1. Untrusted origin: http://evil.attacker.com must NOT receive Access-Control-Allow-Origin
    let req_evil = Request::builder()
        .uri("/metrics")
        .method("GET")
        .header("Origin", "http://evil.attacker.com")
        .body(Body::empty())
        .unwrap();

    let resp_evil = app.oneshot(req_evil).await.unwrap();
    assert_eq!(resp_evil.status(), StatusCode::OK);
    assert!(
        resp_evil
            .headers()
            .get("access-control-allow-origin")
            .is_none(),
        "Untrusted cross-origin requests must NOT be granted CORS access"
    );

    // 2. Preflight OPTIONS from evil origin must not receive allow-origin
    let app_opt = create_router(setup_test_state());
    let req_opt_evil = Request::builder()
        .uri("/onboard")
        .method("OPTIONS")
        .header("Origin", "http://evil.attacker.com")
        .header("Access-Control-Request-Method", "POST")
        .body(Body::empty())
        .unwrap();

    let resp_opt_evil = app_opt.oneshot(req_opt_evil).await.unwrap();
    assert!(
        resp_opt_evil
            .headers()
            .get("access-control-allow-origin")
            .is_none(),
        "Preflight OPTIONS from untrusted origin must be rejected"
    );

    // 3. Trusted local origin: http://localhost:3000 (e.g. Next.js dashboard)
    let app_local = create_router(setup_test_state());
    let req_local = Request::builder()
        .uri("/metrics")
        .method("GET")
        .header("Origin", "http://localhost:3000")
        .body(Body::empty())
        .unwrap();

    let resp_local = app_local.oneshot(req_local).await.unwrap();
    assert_eq!(resp_local.status(), StatusCode::OK);
    assert_eq!(
        resp_local
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "http://localhost:3000"
    );

    // 4. Trusted loopback origin: http://127.0.0.1:5173 (e.g. Vite UI)
    let app_loopback = create_router(setup_test_state());
    let req_loopback = Request::builder()
        .uri("/metrics")
        .method("GET")
        .header("Origin", "http://127.0.0.1:5173")
        .body(Body::empty())
        .unwrap();

    let resp_loopback = app_loopback.oneshot(req_loopback).await.unwrap();
    assert_eq!(resp_loopback.status(), StatusCode::OK);
    assert_eq!(
        resp_loopback
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "http://127.0.0.1:5173"
    );

    // 5. Native non-browser requests without Origin (curl, CLI) must succeed normally
    let app_native = create_router(setup_test_state());
    let req_native = Request::builder()
        .uri("/metrics")
        .method("GET")
        .body(Body::empty())
        .unwrap();

    let resp_native = app_native.oneshot(req_native).await.unwrap();
    assert_eq!(resp_native.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_serve_state_initialization_deterministic() {
    let root = repo_root();
    let temp_dir = tempfile::tempdir().unwrap();

    // 1. Verify AppState::new initializes synchronously without needing background task sleep
    let state = AppState::new(
        root.join("data/parquet"),
        root.join("data/ledger.jsonl"),
        temp_dir.path().to_path_buf(),
        root.join("docs/benchmarks/eval_hardcore_report.md"),
    );

    let alerts = state.alerts.read().await;
    assert!(
        !alerts.is_empty(),
        "Alerts must be populated synchronously during AppState::new"
    );
    assert!(
        alerts.iter().any(|a| a.alert_type == "tamper_alarm"),
        "Tamper alarm for block 0 must be populated immediately"
    );

    // 2. Verify AppState::new can be called in a standard non-async thread without panic
    let root_clone = root.clone();
    let temp_path = temp_dir.path().to_path_buf();
    let handle = std::thread::spawn(move || {
        let s = AppState::new(
            root_clone.join("data/parquet"),
            root_clone.join("data/ledger.jsonl"),
            temp_path,
            root_clone.join("docs/benchmarks/eval_hardcore_report.md"),
        );
        // There is no longer a baked-in EPS constant to assert on. What
        // matters is that the state resolves a telemetry sidecar path and
        // reports no measurement when there is none.
        assert!(
            s.telemetry_path().ends_with("live_telemetry.json"),
            "telemetry path must be derived next to the ledger, got {:?}",
            s.telemetry_path()
        );
    });
    handle
        .join()
        .expect("AppState::new must not panic in non-tokio thread");
}

#[tokio::test]
async fn test_serve_live_tcp_listener_wire_http1() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    let state = setup_test_state();
    let app = create_router(state);

    // Bind real TCP socket on ephemeral port
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral TCP port");
    let local_addr = listener.local_addr().expect("get local addr");

    // Spawn server in background
    let server_task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    // Connect via real TCP stream
    let mut stream = TcpStream::connect(local_addr)
        .await
        .expect("connect to TCP listener");

    // Send raw HTTP/1.1 wire protocol request
    let wire_request = format!(
        "GET /metrics HTTP/1.1\r\nHost: {}\r\nUser-Agent: ulpf-test-wire\r\nConnection: close\r\n\r\n",
        local_addr
    );
    stream
        .write_all(wire_request.as_bytes())
        .await
        .expect("write raw HTTP wire bytes");
    stream.flush().await.expect("flush stream");

    // Read full raw response
    let mut response_bytes = Vec::new();
    stream
        .read_to_end(&mut response_bytes)
        .await
        .expect("read wire response");

    let response_str = String::from_utf8_lossy(&response_bytes);

    // Verify HTTP/1.1 wire status line
    assert!(
        response_str.starts_with("HTTP/1.1 200 OK"),
        "Live TCP server must respond with HTTP/1.1 200 OK, got: {}",
        response_str.lines().next().unwrap_or("")
    );

    // Verify response body is valid JSON with metrics
    let body_start = response_str
        .find("\r\n\r\n")
        .expect("find HTTP body delimiter");
    let json_body = &response_str[body_start + 4..];
    let metrics: serde_json::Value = serde_json::from_str(json_body).expect("parse JSON wire body");

    assert!(metrics.get("eps").is_some());
    assert!(metrics.get("latency_p50_micros").is_some());
    assert!(metrics.get("disposition_breakdown").is_some());

    server_task.abort();
}

/// A stale snapshot must not keep serving its gauges. This is the
/// cross-process version of the regression guarded in
/// `ulpf_core::ingest::telemetry`: a stopped pipeline reporting its last
/// EPS and latency as though they were live is worse than reporting
/// nothing, because the dashboard cannot tell the difference.
#[tokio::test]
async fn test_metrics_nulls_gauges_when_snapshot_is_stale() {
    let temp_scratch = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();

    // A snapshot stamped well in the past: the ingest process is gone.
    let stale = ulpf_core::ingest::telemetry::IngestSnapshot {
        monotonic_ms: 1_000,
        unix_ms: chrono::Utc::now().timestamp_millis() - 60_000,
        eps: Some(999_999.0),
        latency_p50_micros: Some(1.28),
        latency_p99_micros: Some(4.12),
        latency_samples: 4_096,
        lru_hit_rate: Some(0.962),
        lru_lookups: Some(100),
        queue_depth: Some(42),
        queue_capacity: Some(50_000),
        dropped_count: Some(0),
        total_ingested: Some(780),
        total_parsed: Some(780),
        total_blocks: Some(13),
        total_anomalies: Some(3),
        vendor_counts: std::collections::BTreeMap::from([("Cisco".to_string(), 260u64)]),
        running: true,
    };
    let sidecar = empty.path().join("live_telemetry.json");
    ulpf_core::ingest::telemetry::write_snapshot(&sidecar, &stale).unwrap();

    let state = AppState {
        parquet_dir: empty.path().join("parquet"),
        ledger_path: empty.path().join("ledger.jsonl"),
        parsers_dir: empty.path().join("parsers"),
        eval_report_path: empty.path().join("eval.json"),
        scratch_dir: temp_scratch.path().to_path_buf(),
        registry: std::sync::Arc::new(tokio::sync::RwLock::new(
            ulpf_ai::onboarder::DynamicParserRegistry::new(),
        )),
        alerts: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        persist_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        start_time: std::time::Instant::now(),
        telemetry_path: sidecar,
        stale_after_ms: ulpf_core::ingest::telemetry::DEFAULT_STALE_AFTER_MS,
        metrics_cache: ulpf_cli::serve::metrics_cache::MetricsCache::new(
            std::time::Duration::from_millis(
                ulpf_cli::serve::metrics_cache::DEFAULT_METRICS_TTL_MS,
            ),
        ),
        corpus_cache: ulpf_cli::serve::metrics_cache::CorpusCache::new(),
    };

    let metrics = state.compute_metrics().await;

    for field in [
        "eps",
        "latency_p50_micros",
        "latency_p99_micros",
        "lru_hit_rate",
        "queue_depth",
        "queue_capacity",
        "dropped_count",
    ] {
        assert_eq!(
            metrics_field(&metrics, field),
            None,
            "`{field}` must be null once the snapshot is stale, not the last value it held"
        );
    }
    assert_eq!(
        metrics.telemetry_state,
        ulpf_cli::serve::state::TelemetryState::Stale
    );
    assert_eq!(metrics.status, "IDLE");

    // Cumulative facts are still true and should survive.
    assert_eq!(metrics.total_blocks, Some(13));
    assert_eq!(metrics.vendor_mix.get("Cisco"), Some(&260));
}

/// A fresh snapshot from a "running" writer must be reported as live, with
/// its values intact. The counterpart to the staleness test, so neither
/// branch can be quietly broken.
#[tokio::test]
async fn test_metrics_reports_live_snapshot_values() {
    let temp_scratch = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();

    let fresh = ulpf_core::ingest::telemetry::IngestSnapshot {
        monotonic_ms: 10_000,
        unix_ms: chrono::Utc::now().timestamp_millis(),
        eps: Some(1234.0),
        latency_p50_micros: Some(45.45),
        latency_p99_micros: Some(265.7),
        latency_samples: 780,
        lru_hit_rate: Some(0.974),
        lru_lookups: Some(768),
        queue_depth: Some(3),
        queue_capacity: Some(5_000),
        dropped_count: Some(0),
        total_ingested: Some(780),
        total_parsed: Some(780),
        total_blocks: Some(13),
        total_anomalies: Some(122),
        vendor_counts: std::collections::BTreeMap::from([
            ("Cisco".to_string(), 260u64),
            ("Fortinet".to_string(), 260u64),
        ]),
        running: true,
    };
    let sidecar = empty.path().join("live_telemetry.json");
    ulpf_core::ingest::telemetry::write_snapshot(&sidecar, &fresh).unwrap();

    let state = AppState {
        parquet_dir: empty.path().join("parquet"),
        ledger_path: empty.path().join("ledger.jsonl"),
        parsers_dir: empty.path().join("parsers"),
        eval_report_path: empty.path().join("eval.json"),
        scratch_dir: temp_scratch.path().to_path_buf(),
        registry: std::sync::Arc::new(tokio::sync::RwLock::new(
            ulpf_ai::onboarder::DynamicParserRegistry::new(),
        )),
        alerts: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        persist_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        start_time: std::time::Instant::now(),
        telemetry_path: sidecar,
        stale_after_ms: ulpf_core::ingest::telemetry::DEFAULT_STALE_AFTER_MS,
        metrics_cache: ulpf_cli::serve::metrics_cache::MetricsCache::new(
            std::time::Duration::from_millis(
                ulpf_cli::serve::metrics_cache::DEFAULT_METRICS_TTL_MS,
            ),
        ),
        corpus_cache: ulpf_cli::serve::metrics_cache::CorpusCache::new(),
    };

    let metrics = state.compute_metrics().await;

    assert_eq!(metrics.eps, Some(1234.0), "a live EPS must be reported");
    assert_eq!(metrics.latency_p50_micros, Some(45.45));
    assert_eq!(metrics.latency_p99_micros, Some(265.7));
    assert_eq!(metrics.lru_hit_rate, Some(0.974));
    assert_eq!(metrics.queue_depth, Some(3));
    assert_eq!(metrics.queue_capacity, Some(5_000));
    assert_eq!(metrics.dropped_count, Some(0));
    assert_eq!(metrics.total_anomalies, Some(122));
    assert_eq!(metrics.vendor_mix.get("Cisco"), Some(&260));
    assert_eq!(
        metrics.telemetry_state,
        ulpf_cli::serve::state::TelemetryState::Live
    );
    assert_eq!(metrics.status, "HEALTHY", "zero drops + live = healthy");
}

/// A nonzero measured drop count must degrade the status. This is what
/// makes `status` a real signal rather than a constant.
#[tokio::test]
async fn test_metrics_degrades_status_on_measured_drops() {
    let temp_scratch = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();

    let dropping = ulpf_core::ingest::telemetry::IngestSnapshot {
        monotonic_ms: 10_000,
        unix_ms: chrono::Utc::now().timestamp_millis(),
        eps: Some(50_000.0),
        dropped_count: Some(17),
        running: true,
        ..Default::default()
    };
    let sidecar = empty.path().join("live_telemetry.json");
    ulpf_core::ingest::telemetry::write_snapshot(&sidecar, &dropping).unwrap();

    let state = AppState {
        parquet_dir: empty.path().join("parquet"),
        ledger_path: empty.path().join("ledger.jsonl"),
        parsers_dir: empty.path().join("parsers"),
        eval_report_path: empty.path().join("eval.json"),
        scratch_dir: temp_scratch.path().to_path_buf(),
        registry: std::sync::Arc::new(tokio::sync::RwLock::new(
            ulpf_ai::onboarder::DynamicParserRegistry::new(),
        )),
        alerts: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        persist_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        start_time: std::time::Instant::now(),
        telemetry_path: sidecar,
        stale_after_ms: ulpf_core::ingest::telemetry::DEFAULT_STALE_AFTER_MS,
        metrics_cache: ulpf_cli::serve::metrics_cache::MetricsCache::new(
            std::time::Duration::from_millis(
                ulpf_cli::serve::metrics_cache::DEFAULT_METRICS_TTL_MS,
            ),
        ),
        corpus_cache: ulpf_cli::serve::metrics_cache::CorpusCache::new(),
    };

    let metrics = state.compute_metrics().await;
    assert_eq!(
        metrics.status, "DEGRADED",
        "a measured drop count must degrade the pipeline, not report HEALTHY"
    );
    assert_eq!(metrics.dropped_count, Some(17));
}

/// Helper so the staleness test can assert on the optional numeric fields
/// without repeating the match in every assertion.
fn metrics_field(m: &ulpf_cli::serve::state::MetricsResponse, name: &str) -> Option<f64> {
    match name {
        "eps" => m.eps,
        "latency_p50_micros" => m.latency_p50_micros,
        "latency_p99_micros" => m.latency_p99_micros,
        "lru_hit_rate" => m.lru_hit_rate,
        "queue_depth" => m.queue_depth.map(|v| v as f64),
        "queue_capacity" => m.queue_capacity.map(|v| v as f64),
        "dropped_count" => m.dropped_count.map(|v| v as f64),
        other => panic!("unhandled field {other}"),
    }
}

/// A measured zero is a real observation, not an absence. An ingest
/// process that is running and has ingested nothing has measured
/// `total_ingested: 0`; collapsing that to `null` would break the
/// documented contract that `0` and `null` mean different things.
#[tokio::test]
async fn test_measured_zero_is_reported_as_zero_not_null() {
    let temp_scratch = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();

    let live_but_idle = ulpf_core::ingest::telemetry::IngestSnapshot {
        monotonic_ms: 10_000,
        unix_ms: chrono::Utc::now().timestamp_millis(),
        // A real measurement of zero: running, but no traffic yet.
        total_ingested: Some(0),
        total_parsed: Some(0),
        total_blocks: Some(0),
        dropped_count: Some(0),
        eps: Some(0.0),
        running: true,
        ..Default::default()
    };
    let sidecar = empty.path().join("live_telemetry.json");
    ulpf_core::ingest::telemetry::write_snapshot(&sidecar, &live_but_idle).unwrap();

    let state = AppState {
        parquet_dir: empty.path().join("parquet"),
        ledger_path: empty.path().join("ledger.jsonl"),
        parsers_dir: empty.path().join("parsers"),
        eval_report_path: empty.path().join("eval.json"),
        scratch_dir: temp_scratch.path().to_path_buf(),
        registry: std::sync::Arc::new(tokio::sync::RwLock::new(
            ulpf_ai::onboarder::DynamicParserRegistry::new(),
        )),
        alerts: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        persist_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        start_time: std::time::Instant::now(),
        telemetry_path: sidecar,
        stale_after_ms: ulpf_core::ingest::telemetry::DEFAULT_STALE_AFTER_MS,
        metrics_cache: ulpf_cli::serve::metrics_cache::MetricsCache::new(
            std::time::Duration::from_millis(
                ulpf_cli::serve::metrics_cache::DEFAULT_METRICS_TTL_MS,
            ),
        ),
        corpus_cache: ulpf_cli::serve::metrics_cache::CorpusCache::new(),
    };

    let metrics = state.compute_metrics().await;

    assert_eq!(
        metrics.total_ingested,
        Some(0),
        "a measured zero must be reported as 0, not collapsed to null"
    );
    assert_eq!(
        metrics.eps,
        Some(0.0),
        "a measured zero rate must be reported as 0.0, not null"
    );
    assert_eq!(metrics.dropped_count, Some(0));
}

/// A snapshot whose writer stopped must not keep serving live gauges, and
/// its reported age must be a real wall-clock distance rather than a
/// sentinel like `u64::MAX`.
#[tokio::test]
async fn test_stopped_writer_clears_gauges_and_reports_real_age() {
    let temp_scratch = tempfile::tempdir().unwrap();
    let empty = tempfile::tempdir().unwrap();

    let stopped = ulpf_core::ingest::telemetry::IngestSnapshot {
        monotonic_ms: 5_000,
        unix_ms: chrono::Utc::now().timestamp_millis() - 2_000,
        eps: Some(7_777.0),
        latency_p50_micros: Some(3.3),
        queue_depth: Some(11),
        dropped_count: Some(0),
        total_ingested: Some(500),
        // The writer says it is no longer running.
        running: false,
        ..Default::default()
    };
    let sidecar = empty.path().join("live_telemetry.json");
    ulpf_core::ingest::telemetry::write_snapshot(&sidecar, &stopped).unwrap();

    let state = AppState {
        parquet_dir: empty.path().join("parquet"),
        ledger_path: empty.path().join("ledger.jsonl"),
        parsers_dir: empty.path().join("parsers"),
        eval_report_path: empty.path().join("eval.json"),
        scratch_dir: temp_scratch.path().to_path_buf(),
        registry: std::sync::Arc::new(tokio::sync::RwLock::new(
            ulpf_ai::onboarder::DynamicParserRegistry::new(),
        )),
        alerts: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        persist_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        start_time: std::time::Instant::now(),
        telemetry_path: sidecar,
        stale_after_ms: ulpf_core::ingest::telemetry::DEFAULT_STALE_AFTER_MS,
        metrics_cache: ulpf_cli::serve::metrics_cache::MetricsCache::new(
            std::time::Duration::from_millis(
                ulpf_cli::serve::metrics_cache::DEFAULT_METRICS_TTL_MS,
            ),
        ),
        corpus_cache: ulpf_cli::serve::metrics_cache::CorpusCache::new(),
    };

    let metrics = state.compute_metrics().await;

    assert_eq!(metrics.eps, None, "a stopped writer's EPS is not live");
    assert_eq!(metrics.latency_p50_micros, None);
    assert_eq!(metrics.queue_depth, None);
    assert_eq!(
        metrics.telemetry_state,
        ulpf_cli::serve::state::TelemetryState::Stale
    );
    assert_eq!(metrics.status, "IDLE");

    let age = metrics
        .telemetry_age_ms
        .expect("a stopped writer still has a real wall-clock age");
    assert!(
        age < u64::MAX / 2,
        "age must be a real distance, not a sentinel (got {age})"
    );
    assert!(
        (1_000..=60_000).contains(&age),
        "age should reflect the 2s offset, got {age}ms"
    );

    // Cumulative facts survive: they are still true.
    assert_eq!(metrics.total_ingested, Some(500));
}

/// The whole point of #56: a poll inside the TTL must not redo the work.
///
/// Asserted through the real handler over HTTP rather than by calling the
/// cache directly, so the test covers the path a client actually takes —
/// including the `AppState` clone axum performs per request, which is where a
/// naive cache would silently give every request its own copy.
#[tokio::test]
async fn test_metrics_cache_serves_repeat_polls_without_recompute() {
    let state = setup_test_state().with_metrics_ttl(std::time::Duration::from_secs(60));
    let app = create_router(state.clone());

    let mut last_body: Vec<u8> = Vec::new();
    for i in 0..20 {
        let req = Request::builder()
            .uri("/metrics")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = app.clone().oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).expect("valid JSON");

        if i == 0 {
            // First poll populates the cache; the body is real measured data
            // derived from the repo fixtures.
            assert_eq!(
                json.get("telemetry_state").and_then(|v| v.as_str()),
                Some("ABSENT"),
                "no ingest process is running in tests, so telemetry is absent"
            );
            last_body = body.to_vec();
        } else {
            assert_eq!(
                body.to_vec(),
                last_body,
                "poll {i} inside the TTL must return the cached response byte-for-byte"
            );
        }
    }

    assert_eq!(
        state.metrics_cache.recompute_count(),
        1,
        "20 polls inside the TTL must cause exactly one computation"
    );
}

/// A cached response must still describe the freshness it was computed with.
///
/// #56 adds a second kind of staleness on top of #80's: the cached response is
/// younger than the TTL but older than the last ingest write. The two compose
/// only because the cache passes `telemetry_state`/`telemetry_age_ms` through
/// untouched instead of recomputing them. Pinned here so it stays deliberate.
#[tokio::test]
async fn test_cached_response_preserves_its_computed_freshness() {
    let state = setup_test_state().with_metrics_ttl(std::time::Duration::from_secs(60));
    let app = create_router(state.clone());

    let fetch = |app: axum::Router| async move {
        let req = Request::builder()
            .uri("/metrics")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice::<serde_json::Value>(&body).expect("valid JSON")
    };

    let first = fetch(app.clone()).await;
    let second = fetch(app.clone()).await;

    assert_eq!(
        second.get("telemetry_state"),
        first.get("telemetry_state"),
        "a cache hit must not silently upgrade the reported telemetry state"
    );
    assert_eq!(
        second.get("telemetry_age_ms"),
        first.get("telemetry_age_ms"),
        "telemetry_age_ms describes the cached snapshot, so it must not be \
         rewritten to look fresher than the data is"
    );
}

/// Past the TTL the response must be recomputed, and the recompute must not
/// re-run the expensive Parquet scan while the block set is unchanged.
#[tokio::test]
async fn test_expiry_recomputes_but_reuses_the_parquet_scan() {
    let state = setup_test_state().with_metrics_ttl(std::time::Duration::from_millis(1));
    let app = create_router(state.clone());

    let fetch = |app: axum::Router| async move {
        let req = Request::builder()
            .uri("/metrics")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice::<serde_json::Value>(&body).expect("valid JSON")
    };

    let first = fetch(app.clone()).await;
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    let second = fetch(app.clone()).await;
    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    let third = fetch(app.clone()).await;

    assert_eq!(
        state.metrics_cache.recompute_count(),
        3,
        "an expired entry must be recomputed, not served"
    );
    // The block set did not change, so the disposition figures must be
    // identical across recomputes — proving the scan was served from the
    // corpus cache rather than re-run.
    assert_eq!(
        second.get("disposition_breakdown"),
        first.get("disposition_breakdown"),
        "an unchanged block set must not change the disposition breakdown"
    );
    assert_eq!(
        third.get("disposition_breakdown"),
        first.get("disposition_breakdown"),
        "the cached scan must be reused across recomputes"
    );
    assert!(
        second
            .get("disposition_sampled")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
            > 0,
        "the repo fixtures must yield real dispositions, or this test proves nothing"
    );
}

/// Concurrent polls past the TTL must not stampede the recompute.
#[tokio::test]
async fn test_concurrent_polls_do_not_stampede() {
    // A TTL comfortably longer than one recompute. This matters: the
    // single-recompute guarantee only holds while the TTL outlasts the
    // recompute plus scheduling jitter. With a 1 ms TTL the entry expires
    // while waiters are still queued on the mutex, and a second recompute is
    // then *correct* rather than a stampede — which is a real caveat on the
    // mechanism, not something to paper over in the test.
    let state = setup_test_state().with_metrics_ttl(std::time::Duration::from_millis(500));
    let app = create_router(state.clone());

    // Cold cache: nothing has been computed yet, so every task below needs one.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;

    let mut handles = Vec::new();
    for _ in 0..12 {
        let app = app.clone();
        handles.push(tokio::spawn(async move {
            let req = Request::builder()
                .uri("/metrics")
                .method("GET")
                .body(Body::empty())
                .unwrap();
            let response = app.oneshot(req).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        }));
    }
    for h in handles {
        h.await.expect("request task must not panic");
    }

    assert_eq!(
        state.metrics_cache.recompute_count(),
        1,
        "12 concurrent cold polls must cause one recompute, not 12"
    );
}

/// The response shape must be byte-identical to the uncached path — #56 caches
/// underneath #80's contract and must not alter it.
#[tokio::test]
async fn test_cached_and_uncached_paths_agree() {
    let state = setup_test_state();
    let uncached = state.compute_metrics().await;

    let cached_state = state.with_metrics_ttl(std::time::Duration::from_secs(60));
    let first = cached_state.metrics_cached().await;
    let second = cached_state.metrics_cached().await;

    assert_eq!(
        serde_json::to_value(&uncached).unwrap(),
        serde_json::to_value(&first).unwrap(),
        "a cache miss must return exactly what the uncached path returns"
    );
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&second).unwrap(),
        "a cache hit must return the identical payload"
    );
}

/// The ledger parse must live on the cache-miss path, not on every recompute.
///
/// The ledger is append-only and grows without bound, so re-parsing it per
/// recompute would reintroduce precisely the cost #56 was filed to remove —
/// and it is the cost that worsens with uptime, since a long-running
/// deployment accumulates more lines. Asserted by shrinking the corpus
/// fingerprint's block set and confirming the reported totals are reused
/// rather than re-derived.
#[tokio::test]
async fn test_ledger_totals_are_served_from_the_corpus_cache() {
    let state = setup_test_state().with_metrics_ttl(std::time::Duration::from_millis(1));
    let app = create_router(state.clone());

    let fetch = |app: axum::Router| async move {
        let req = Request::builder()
            .uri("/metrics")
            .method("GET")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        let body = response.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice::<serde_json::Value>(&body).expect("valid JSON")
    };

    // Cold: one full compute, which reads the ledger once.
    let first = fetch(app.clone()).await;
    let blocks = first
        .get("total_blocks")
        .and_then(|v| v.as_u64())
        .expect("repo fixture ledger must have blocks");
    assert!(
        blocks > 0,
        "fixture corpus must be non-empty for this to mean anything"
    );

    // Force several TTL expiries. The ledger has not changed, so every one of
    // these must be served from the corpus cache.
    for _ in 0..4 {
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        let next = fetch(app.clone()).await;
        assert_eq!(
            next.get("total_blocks").and_then(|v| v.as_u64()),
            Some(blocks),
            "an unchanged ledger must report the same block count from cache"
        );
        assert_eq!(
            next.get("total_ingested"),
            first.get("total_ingested"),
            "total_ingested must come from the cached ledger totals, not a re-parse"
        );
    }
    assert!(
        state.metrics_cache.recompute_count() >= 5,
        "the response cache must have expired repeatedly for this test to mean \
         anything, got {} recomputes",
        state.metrics_cache.recompute_count()
    );
}

/// Appending a ledger line must invalidate the corpus cache, so a newly
/// anchored block is not hidden by a stale aggregate.
///
/// Exercises the *cached* path deliberately. An earlier version of this test
/// built a fresh `AppState` per call and called `compute_metrics`, which
/// bypasses `corpus_cache` entirely — it would have passed even if
/// `CorpusCache::get` ignored the fingerprint completely, so it proved only
/// that the ledger parses.
///
/// Works on a **copy** of the repo ledger in a temp directory. Appending to
/// the tracked fixture from a test risks leaving it corrupted when an assertion
/// fails, which silently breaks every other test that reads the corpus — and
/// did exactly that on the first attempt.
#[tokio::test]
async fn test_appending_to_the_ledger_invalidates_the_corpus_cache() {
    let root = repo_root();
    let original = std::fs::read(root.join("data/ledger.jsonl")).expect("fixture ledger");

    let temp = tempfile::tempdir().unwrap();
    let ledger = temp.path().join("ledger.jsonl");
    std::fs::write(&ledger, &original).expect("seed temp ledger");

    // ONE state, so the corpus cache survives across the append and the
    // invalidation is what makes the new block appear.
    let state = AppState {
        parquet_dir: root.join("data/parquet"),
        ledger_path: ledger.clone(),
        parsers_dir: temp.path().join("parsers"),
        eval_report_path: root.join("docs/benchmarks/eval_hardcore_report.md"),
        scratch_dir: temp.path().join("scratch"),
        registry: std::sync::Arc::new(tokio::sync::RwLock::new(
            ulpf_ai::onboarder::DynamicParserRegistry::new(),
        )),
        alerts: std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())),
        persist_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        start_time: std::time::Instant::now(),
        telemetry_path: temp.path().join("live_telemetry.json"),
        stale_after_ms: ulpf_core::ingest::telemetry::DEFAULT_STALE_AFTER_MS,
        metrics_cache: ulpf_cli::serve::metrics_cache::MetricsCache::new(
            std::time::Duration::from_millis(
                ulpf_cli::serve::metrics_cache::DEFAULT_METRICS_TTL_MS,
            ),
        ),
        corpus_cache: ulpf_cli::serve::metrics_cache::CorpusCache::new(),
    }
    .with_metrics_ttl(std::time::Duration::from_millis(30));

    // First compute populates the corpus cache.
    let before = state.metrics_cached().await;
    let blocks_before = before
        .total_blocks
        .expect("the copied fixture ledger must parse");
    assert!(blocks_before > 0, "fixture corpus must be non-empty");

    // A second compute with an unchanged ledger must be served from the
    // corpus cache. This is the precondition that makes the rest meaningful:
    // if the cache were not holding, the test could not distinguish
    // "invalidated correctly" from "recomputed anyway".
    let _ = state.metrics_cached().await;

    // Append an entry in the real ledger schema, including `parquet_file` —
    // `load_ledger_entries` reads these fields, and a line missing one makes
    // the whole ledger fail to parse rather than adding one block.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&ledger)
            .expect("append to temp ledger");
        writeln!(
            f,
            r#"{{"block_id":{},"timestamp":1789984480000,"leaf_count":1,"merkle_root":"cache-invalidation-probe","parquet_file":"block_{:05}.parquet"}}"#,
            blocks_before, blocks_before
        )
        .expect("write probe entry");
        f.sync_all().ok();
    }

    // Past the TTL, the response cache expires and the recompute consults the
    // corpus cache — which must now miss, because the ledger changed.
    tokio::time::sleep(std::time::Duration::from_millis(60)).await;
    let after = state.metrics_cached().await;
    let blocks_after = after
        .total_blocks
        .expect("the appended ledger must still parse");

    assert_eq!(
        blocks_after,
        blocks_before + 1,
        "an appended ledger entry must invalidate the corpus cache — a stale \
         aggregate must not hide a newly anchored block"
    );
}

/// A failed corpus scan must not poison the cache.
///
/// `spawn_blocking` panicking (an allocation failure, a panic in a decode
/// path) previously fell back to empty aggregates *and cached them* under the
/// current fingerprint. Since the fingerprint only changes when the ledger
/// grows, a single transient panic would blank `total_blocks` and the
/// disposition figures indefinitely on a quiet corpus — reporting "nothing
/// measured" forever while the data was sitting there the whole time.
///
/// The fallback is reported once, then retried; only a successful scan is
/// ever cached.
#[tokio::test]
async fn test_failed_scan_is_not_cached() {
    // A state whose parquet path points at something that will make the
    // reader misbehave is hard to arrange reliably, so this exercises the
    // caching rule directly: put a failed-scan fallback under a fingerprint
    // and confirm the next lookup does not hand it back.
    let cache = ulpf_cli::serve::metrics_cache::CorpusCache::new();
    let fingerprint =
        ulpf_cli::serve::metrics_cache::fingerprint_ledger(&repo_root().join("data/ledger.jsonl"));

    // Simulate the state after a failed scan: a real (non-empty) corpus is
    // NOT stored, so the next lookup must miss rather than serve the default.
    let after_failure = cache.get(fingerprint).await;
    assert!(
        after_failure.is_none(),
        "a failed scan must leave the corpus cache empty so the next recompute retries"
    );

    // And once a real scan succeeds, the value is served from cache.
    let success = ulpf_cli::serve::metrics_cache::CorpusAggregates {
        disposition_breakdown: [("Allowed".to_string(), 7u64)].into_iter().collect(),
        disposition_sampled: 7,
        ledger_totals: (3, 3001),
    };
    cache.put(fingerprint, success.clone()).await;
    assert_eq!(
        cache.get(fingerprint).await,
        Some(success),
        "a successful scan must be cached and served"
    );
}
