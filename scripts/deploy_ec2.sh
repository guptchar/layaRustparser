#!/usr/bin/env bash
# ==============================================================================
# scripts/deploy_ec2.sh
# Automated Zero-Downtime Deployment & Build Script for AWS EC2
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "=========================================================="
echo "  ULPF Production Deployment Agent"
echo "  Timestamp: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo "  Root:      $APP_DIR"
echo "=========================================================="

cd "$APP_DIR"

# 1. Environment Configuration
echo "==> [1/5] Loading toolchains and environment..."
if [ -f "$HOME/.cargo/env" ]; then
    source "$HOME/.cargo/env"
fi
export PATH="$HOME/.cargo/bin:$HOME/.nvm/versions/node/$(node -v 2>/dev/null || true)/bin:$PATH"

if ! command -v cargo &> /dev/null; then
    echo "ERROR: 'cargo' toolchain not found in PATH ($PATH)."
    exit 1
fi
if ! command -v npm &> /dev/null; then
    echo "ERROR: 'npm' not found in PATH."
    exit 1
fi

echo "    Rust:   $(cargo --version)"
echo "    Node:   $(node --version)"
echo "    Commit: $(git rev-parse --short HEAD) - $(git log -1 --pretty=%s)"

# 2. Compile Rust Backend Binaries (Lean Mode)
echo "==> [2/5] Compiling Rust release binaries..."
export CARGO_INCREMENTAL=0

# Truncate logs if they exceed 10MB to save space
for logfile in "$APP_DIR/serve.log" "$APP_DIR/frontend.log" "$APP_DIR/ingest.log"; do
    if [ -f "$logfile" ] && [ $(stat -c%s "$logfile" 2>/dev/null || echo 0) -gt 10485760 ]; then
        truncate -s 2M "$logfile"
    fi
done

cargo build --release -p ulpf-cli -p ulpf-generator

if [ ! -f "$APP_DIR/target/release/ulpf" ]; then
    echo "ERROR: Expected binary $APP_DIR/target/release/ulpf was not generated."
    exit 1
fi
echo "    Binaries compiled successfully: $(ls -lh target/release/ulpf | awk '{print $5, $9}')"

# Free up intermediate compile objects while keeping the binary
rm -rf "$APP_DIR/target/release/incremental" "$APP_DIR/target/debug" 2>/dev/null || true


# 3. Build Next.js Production Frontend
echo "==> [3/5] Building Next.js frontend..."
cd "$APP_DIR/frontend/laya-frontend"

npm install --prefer-offline --no-audit
npm run build

cd "$APP_DIR"
echo "    Next.js production bundle generated successfully."

# 4. Service Restart (Systemd or Background Daemon)
echo "==> [4/5] Cycling services..."

if systemctl is-active --quiet ulpf-backend.service 2>/dev/null || systemctl is-enabled --quiet ulpf-backend.service 2>/dev/null; then
    echo "    Detected systemd management. Restarting units..."
    sudo systemctl restart ulpf-backend.service
    sudo systemctl restart ulpf-frontend.service
    if systemctl list-unit-files | grep -q "ulpf-ingest.service"; then
        sudo systemctl restart ulpf-ingest.service || true
    fi
else
    echo "    Systemd units not found. Starting full demo stack via start_demo_stack.sh..."
    "$APP_DIR/scripts/start_demo_stack.sh"
fi

# 5. Health Check Audit
echo "==> [5/5] Performing loopback health checks..."
MAX_ATTEMPTS=20
SUCCESS=0

for i in $(seq 1 $MAX_ATTEMPTS); do
    echo "    Health audit attempt ($i/$MAX_ATTEMPTS)..."
    
    # Test Backend Metrics Endpoint
    BACKEND_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/metrics 2>/dev/null || echo "000")
    
    # Test Frontend Dashboard
    FRONTEND_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3000 2>/dev/null || echo "000")

    if [ "$BACKEND_STATUS" = "200" ] && [ "$FRONTEND_STATUS" = "200" ]; then
        METRICS_JSON=$(curl -s http://127.0.0.1:8080/metrics 2>/dev/null || echo "{}")
        TEL_STATE=$(echo "$METRICS_JSON" | (jq -r '.telemetry_state // "UNKNOWN"' 2>/dev/null || echo "UNKNOWN"))
        EPS_VAL=$(echo "$METRICS_JSON" | (jq -r '.eps // "null"' 2>/dev/null || echo "null"))
        TOTAL_INGESTED=$(echo "$METRICS_JSON" | (jq -r '.total_ingested // "0"' 2>/dev/null || echo "0"))

        echo "    Status: API=$BACKEND_STATUS | Telemetry=$TEL_STATE | Ingest EPS=$EPS_VAL | Total Ingested=$TOTAL_INGESTED | Frontend=$FRONTEND_STATUS"

        if [ "$TEL_STATE" = "LIVE" ]; then
            echo "=========================================================="
            echo "  DEPLOYMENT SUCCEEDED ✓"
            echo "  Backend API:    http://127.0.0.1:8080/metrics (HTTP $BACKEND_STATUS, State: $TEL_STATE)"
            echo "  Ingest Rate:    $EPS_VAL EPS (Total Ingested: $TOTAL_INGESTED)"
            echo "  Frontend UI:    http://127.0.0.1:3000         (HTTP $FRONTEND_STATUS)"
            echo "=========================================================="
            SUCCESS=1
            break
        else
            echo "    Telemetry state is $TEL_STATE (waiting for LIVE stream)..."
        fi
    fi
    sleep 3
done

if [ "$SUCCESS" -eq 0 ]; then
    echo "=========================================================="
    echo "  DEPLOYMENT HEALTH CHECK FAILED ✗"
    echo "  Backend HTTP:  $BACKEND_STATUS (expected 200)"
    echo "  Frontend HTTP: $FRONTEND_STATUS (expected 200)"
    echo "  Telemetry:     ${TEL_STATE:-UNKNOWN} (expected LIVE)"
    echo "=========================================================="
    echo "--- Last 20 lines of serve.log ---"
    tail -n 20 "$APP_DIR/serve.log" 2>/dev/null || true
    echo "--- Last 20 lines of frontend.log ---"
    tail -n 20 "$APP_DIR/frontend.log" 2>/dev/null || true
    echo "--- Last 20 lines of ingest.log ---"
    tail -n 20 "$APP_DIR/ingest.log" 2>/dev/null || true
    echo "--- Last 20 lines of demo_loop.log ---"
    tail -n 20 "$APP_DIR/demo_loop.log" 2>/dev/null || true
    exit 1
fi
