//! Regenerates `data/fixtures/api/metrics.json` and `alerts.json` by calling
//! the real `AppState` against the real fixtures, so the committed examples
//! cannot drift from the implementation.
//!
//! Run from the repo root: `cargo run -p ulpf-cli --bin ulpf_fixture_gen`.
//! Exists as a bin target rather than a test so a stale fixture is easy to
//! regenerate, and so the values are produced by the same code path the server
//! uses rather than hand-copied into JSON.

use std::path::PathBuf;

use ulpf_cli::serve::AppState;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("canonicalize repo root")
}

#[tokio::main]
async fn main() {
    let root = repo_root();
    let state = AppState::new(
        root.join("data/parquet"),
        root.join("data/ledger.jsonl"),
        root.join("data/parsers"),
        root.join("docs/benchmarks/eval_hardcore_report.md"),
    );

    let metrics =
        serde_json::to_string_pretty(&state.compute_metrics().await).expect("serialize metrics");
    std::fs::write(
        root.join("data/fixtures/api/metrics.json"),
        format!("{metrics}\n"),
    )
    .expect("write metrics fixture");

    // Alerts are derived from a real block verification, so generate them the
    // same way the server seeds them.
    let alerts = serde_json::to_string_pretty(&AppState::compute_initial_alerts(
        &root.join("data/parquet"),
        &root.join("data/ledger.jsonl"),
    ))
    .expect("serialize alerts");
    std::fs::write(
        root.join("data/fixtures/api/alerts.json"),
        format!("{alerts}\n"),
    )
    .expect("write alerts fixture");

    println!("regenerated data/fixtures/api/metrics.json and alerts.json");
}
