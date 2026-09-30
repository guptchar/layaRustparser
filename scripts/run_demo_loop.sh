#!/usr/bin/env bash
# ==============================================================================
# scripts/run_demo_loop.sh
# Continuous Demo Stream Replay Supervisor for AWS EC2 (NTRO / SIH26156)
# ==============================================================================
# Ensures that after all logs in the dataset are streamed and ingested,
# the generator automatically pauses briefly and replays from the beginning,
# while maintaining bounded Parquet storage to prevent EC2 disk exhaustion.
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

ULPF_BIN="$ROOT_DIR/target/release/ulpf"
GEN_BIN="$ROOT_DIR/target/release/ulpf-generator"
PARQUET_DIR="$ROOT_DIR/data/parquet"
LEDGER_FILE="$ROOT_DIR/data/ledger.jsonl"
RATE=${DEMO_RATE:-250}
CYCLE_DURATION=${DEMO_CYCLE_SECS:-40}
MAX_BLOCKS=${DEMO_MAX_BLOCKS:-50}

echo "=========================================================="
echo "  ULPF Continuous Demo Stream Supervisor (EC2 Demo Mode)"
echo "=========================================================="
echo "  Root Directory  : $ROOT_DIR"
echo "  Target Rate     : $RATE EPS"
echo "  Cycle Duration  : $CYCLE_DURATION seconds (~$((RATE * CYCLE_DURATION)) logs/cycle)"
echo "  Max Parquet     : $MAX_BLOCKS blocks (~$((MAX_BLOCKS * 700 / 1024)) MB retention bound)"
echo "=========================================================="

if [ ! -f "$ULPF_BIN" ] || [ ! -f "$GEN_BIN" ]; then
    echo "[!] Compiling release binaries..."
    cargo build --release -p ulpf-cli -p ulpf-generator
fi

# Ensure data directories exist
mkdir -p "$PARQUET_DIR" "$ROOT_DIR/data/parsers"

# Cleanup function on exit
cleanup() {
    echo -e "\n[!] Shutting down ULPF demo supervisor..."
    pkill -P $$ 2>/dev/null || true
    pkill -9 -f "$GEN_BIN" 2>/dev/null || true
    pkill -9 -f "ulpf ingest" 2>/dev/null || true
    echo "[✓] Demo supervisor stopped cleanly."
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# Step 1: Terminate any stale duplicate demo supervisor loops
CURRENT_PID=$$
for pid in $(pgrep -f "run_demo_loop.sh" 2>/dev/null || true); do
    if [ "$pid" != "$CURRENT_PID" ]; then
        echo "[!] Terminating stale demo loop supervisor PID $pid..."
        kill -9 "$pid" 2>/dev/null || true
    fi
done

pkill -9 -f "ulpf ingest" 2>/dev/null || true
pkill -9 -f "ulpf-generator" 2>/dev/null || true
sleep 1

# Helper to ensure ULPF Ingest Engine is running and healthy
ensure_ingest_running() {
    if ! pgrep -f "ulpf ingest" > /dev/null 2>&1; then
        echo "==> [ULPF Demo Loop] Ingest engine not active. Launching ULPF Ingest (UDP/TCP 5140)..."
        nohup "$ULPF_BIN" ingest \
            --udp 0.0.0.0:5140 \
            --tcp 0.0.0.0:5140 \
            --parquet-dir "$PARQUET_DIR" \
            --ledger "$LEDGER_FILE" \
            --batch-size 1000 \
            --batch-timeout 1000 >> "$ROOT_DIR/ingest.log" 2>&1 &
        sleep 2
        if ! pgrep -f "ulpf ingest" > /dev/null 2>&1; then
            echo "[✗] Ingest engine failed to start. Last log lines:"
            tail -n 10 "$ROOT_DIR/ingest.log" 2>/dev/null || true
        else
            echo "[✓] Ingest engine online (PID: $(pgrep -f "ulpf ingest" | tr '\n' ' '))."
        fi
    fi
}

# Step 2: Ensure ULPF Ingest Engine is running
echo "==> [1/3] Initializing ULPF Ingest Engine..."
ensure_ingest_running

# Step 3: Run continuous generation replay loop
echo "==> [2/3] Starting continuous multi-vendor replay cycles..."
CYCLE=1

while true; do
    ensure_ingest_running
    echo "----------------------------------------------------------"
    echo "[ULPF Demo Loop] Starting replay cycle #$CYCLE (Streaming all datasets at $RATE EPS)..."
    echo "----------------------------------------------------------"

    # Stream logs across all datasets (Cisco, FortiGate, PAN-OS, Suricata, pfSense, Kaggle)
    "$GEN_BIN" \
        --target 127.0.0.1:5140 \
        --proto udp \
        --rate "$RATE" \
        --duration "$CYCLE_DURATION" \
        --dataset all || true

    echo ""
    echo "[✓] [ULPF Demo Loop] Cycle #$CYCLE finished all logs."
    echo "[*] [ULPF Demo Loop] Pausing 3s before restarting from the beginning..."
    sleep 3

    # Step 4: Storage Maintenance (Keep newest blocks, prune older to prevent disk full)
    PARQUET_COUNT=$(ls -1 "$PARQUET_DIR"/*.parquet 2>/dev/null | wc -l || echo 0)
    if [ "$PARQUET_COUNT" -gt "$MAX_BLOCKS" ]; then
        EXCESS=$((PARQUET_COUNT - MAX_BLOCKS))
        echo "[*] Pruning $EXCESS oldest Parquet blocks to maintain $MAX_BLOCKS block disk bound..."
        ls -1t "$PARQUET_DIR"/*.parquet 2>/dev/null | tail -n "$EXCESS" | xargs -r rm -f
    fi

    CYCLE=$((CYCLE + 1))
done
