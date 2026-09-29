pub mod handlers;
pub mod metrics_cache;
pub mod state;

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use axum::http::HeaderValue;
use axum::routing::{get, post};
use axum::Router;
use clap::Args;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tracing::info;

pub use state::AppState;

#[derive(Args, Debug, Clone)]
pub struct ServeArgs {
    /// Port to bind the HTTP backend server
    #[arg(short, long, default_value_t = 8080)]
    pub port: u16,

    /// Interface address to bind
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Directory for Parquet archive blocks
    #[arg(long, default_value = "data/parquet")]
    pub parquet_dir: PathBuf,

    /// Path to append-only cryptographic ledger file
    #[arg(long, default_value = "data/ledger.jsonl")]
    pub ledger: PathBuf,

    /// Directory for dynamic parser specifications
    #[arg(long, default_value = "data/parsers")]
    pub parsers_dir: PathBuf,

    /// Optional path to benchmark evaluation JSON report
    #[arg(long, default_value = "eval_report.json")]
    pub eval_report: PathBuf,
}

/// Constructs the complete Axum router with state and CORS.
pub fn create_router(state: AppState) -> Router {
    // Air-gapped CORS policy: strictly allow localhost and 127.0.0.1 origins
    // to prevent malicious cross-origin websites from triggering mutating endpoints.
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|origin: &HeaderValue, _| {
            if let Ok(s) = origin.to_str() {
                s.starts_with("http://localhost:")
                    || s.starts_with("http://127.0.0.1:")
                    || s == "http://localhost"
                    || s == "http://127.0.0.1"
                    || s.starts_with("https://localhost:")
                    || s.starts_with("https://127.0.0.1:")
            } else {
                false
            }
        }))
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::header::ACCEPT,
        ]);

    Router::new()
        // Core telemetry & alerts (#13 Dashboard)
        .route("/metrics", get(handlers::get_metrics))
        .route("/alerts", get(handlers::get_alerts))
        // Forensic investigation & records (#14 Search)
        .route("/blocks", get(handlers::get_blocks))
        .route("/blocks/{id}/records", get(handlers::get_block_records))
        .route("/prove/{block}/{leaf}", get(handlers::get_prove_inclusion))
        .route("/export/bundle/{id}", get(handlers::get_export_bundle))
        // Parser registry & onboarding (#15 Parser / Integrity Management)
        .route("/parsers", get(handlers::get_parsers))
        .route("/parsers/test", post(handlers::post_parsers_test))
        .route("/onboard", post(handlers::post_onboard))
        // System status & isolated adversarial drill
        .route("/system", get(handlers::get_system))
        .route("/tamper/drill", post(handlers::post_tamper_drill))
        .layer(cors)
        .with_state(state)
}

/// Runs the `ulpf serve` HTTP backend until SIGINT/SIGTERM.
pub async fn run_serve(args: ServeArgs) -> Result<()> {
    println!(
        "\x1b[1;36m====================================================================\x1b[0m"
    );
    println!(
        "\x1b[1;32m      ULPF Air-Gapped High-Performance REST API Backend             \x1b[0m"
    );
    println!(
        "\x1b[1;36m====================================================================\x1b[0m"
    );
    println!("  HTTP Listen Addr  : http://{}:{}", args.host, args.port);
    println!("  Parquet Archive   : {}", args.parquet_dir.display());
    println!("  Merkle Ledger     : {}", args.ledger.display());
    println!("  Parsers Registry  : {}", args.parsers_dir.display());
    println!("  Wire Protocols    : HTTP/1.1 (High-Performance REST)");
    println!("  Environment       : 100% Air-Gapped (Zero Cloud/CDN Dependencies)");
    println!(
        "\x1b[1;36m--------------------------------------------------------------------\x1b[0m"
    );

    let state = AppState::new(
        args.parquet_dir,
        args.ledger,
        args.parsers_dir,
        args.eval_report,
    );

    let app = create_router(state);

    let addr_str = format!("{}:{}", args.host, args.port);
    let addr: SocketAddr = addr_str
        .parse()
        .with_context(|| format!("Failed to parse bind address {}", addr_str))?;

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind TCP listener on {}", addr))?;

    info!(
        "[+] ULPF backend active on http://{} (Ready for Frontend UI & SIEM)",
        addr
    );

    println!("\x1b[1;32m[+] Server running. Waiting for dashboard requests...\x1b[0m");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Server error during execution")?;

    println!("\n\x1b[1;33m[ULPF SERVE] Server shut down gracefully.\x1b[0m");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install signal handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}
