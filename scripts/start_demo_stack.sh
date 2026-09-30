#!/usr/bin/env bash
# ==============================================================================
# scripts/start_demo_stack.sh
# One-Click Full Stack Demo Launcher for AWS EC2 (Frontend + Backend + Demo Loop)
# ==============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "=========================================================="
echo "  ULPF Full Stack Demo Launcher (EC2)"
echo "=========================================================="

# Clean up previous instances with strict pattern matching
echo "==> [1/4] Stopping existing processes..."
pkill -9 -f "run_demo_loop.sh" 2>/dev/null || true
pkill -9 -f "ulpf serve" 2>/dev/null || true
pkill -9 -f "ulpf ingest" 2>/dev/null || true
pkill -9 -f "ulpf-generator" 2>/dev/null || true
pkill -9 -f "next-server" 2>/dev/null || true
pkill -9 -f "node.*next.*start" 2>/dev/null || true
sleep 2

# Truncate logs if large
for f in "$ROOT_DIR/serve.log" "$ROOT_DIR/frontend.log" "$ROOT_DIR/ingest.log" "$ROOT_DIR/demo_loop.log"; do
    if [ -f "$f" ] && [ $(stat -c%s "$f" 2>/dev/null || echo 0) -gt 5242880 ]; then
        truncate -s 1M "$f"
    fi
done

# Prune excess parquet blocks if > 50
mkdir -p "$ROOT_DIR/data/parquet" "$ROOT_DIR/data/parsers"
PARQUET_COUNT=$(ls -1 "$ROOT_DIR/data/parquet"/*.parquet 2>/dev/null | wc -l || echo 0)
if [ "$PARQUET_COUNT" -gt 50 ]; then
    EXCESS=$((PARQUET_COUNT - 50))
    echo "    Pruning $EXCESS excess Parquet blocks for lean storage..."
    ls -1t "$ROOT_DIR/data/parquet"/*.parquet 2>/dev/null | tail -n "$EXCESS" | xargs -r rm -f
fi

# Step 2: Start Backend REST API Server
echo "==> [2/4] Starting ULPF Backend REST API (port 8080)..."
nohup "$ROOT_DIR/target/release/ulpf" serve --port 8080 --host 0.0.0.0 > "$ROOT_DIR/serve.log" 2>&1 &
sleep 2

# Step 3: Start Next.js Frontend Server
echo "==> [3/4] Starting Next.js Dashboard UI (port 3000)..."
cd "$ROOT_DIR/frontend/laya-frontend"
nohup npx next start -p 3000 -H 0.0.0.0 > "$ROOT_DIR/frontend.log" 2>&1 &
cd "$ROOT_DIR"
sleep 2

# Step 4: Start Continuous Demo Replay Supervisor
echo "==> [4/4] Starting Continuous Demo Stream Replay Supervisor..."
nohup "$ROOT_DIR/scripts/run_demo_loop.sh" > "$ROOT_DIR/demo_loop.log" 2>&1 &

sleep 3
echo "=========================================================="
echo "  [✓] All ULPF Services Active and Running in Continuous Demo Loop!"
echo "  - Frontend UI    : http://16.4.38.85:3000"
echo "  - Backend REST   : http://16.4.38.85:8080/metrics"
echo "  - Stream Supervisor: Cycling all logs every 40s with auto-restart"
echo "=========================================================="
