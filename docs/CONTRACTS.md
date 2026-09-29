# ULPF Backend API Contract (`CONTRACTS.md`)

> **For Frontend Developers (Issues #13, #14, #15)**  
> This document specifies all HTTP REST API endpoints provided by `ulpf serve`.  
> You can code your frontend pages directly against these specifications using the checked-in sample mock JSON fixtures located at [`data/fixtures/api/`](../data/fixtures/api).

---

## 1. Quick Start & Server Execution

### Starting the Backend
Run from the repository root:
```bash
./target/release/ulpf serve --port 8080
# Or bind to all interfaces for remote/Docker access:
./target/release/ulpf serve --port 8080 --host 0.0.0.0
```
- **Base URL**: `http://localhost:8080` (or `http://127.0.0.1:8080`)
- **Wire Protocols Supported**: **HTTP/1.1** (High-Performance REST). For production deployments requiring HTTP/2 or HTTPS, front with a local reverse proxy (Caddy / Nginx) terminating TLS with ALPN.
- **CORS Policy**: Restricted strictly to loopback origins (`http://localhost:*`, `http://127.0.0.1:*`) — your Next.js/React development server (e.g. `http://localhost:3000`) can make fetch calls directly, while untrusted external web origins are rejected.
- **Air-Gapped Guarantee**: The backend makes zero external network or cloud requests.

---

## 2. Frontend Page Integration Mapping

| Page / Issue | Relevant Endpoints | Mock Fixture File |
| :--- | :--- | :--- |
| **#13 Analyst Dashboard** | `GET /metrics`<br>`GET /alerts` | [`data/fixtures/api/metrics.json`](../data/fixtures/api/metrics.json)<br>[`data/fixtures/api/alerts.json`](../data/fixtures/api/alerts.json) |
| **#14 Investigation & Courtroom Export** | `GET /blocks`<br>`GET /blocks/:id/records`<br>`GET /prove/:block/:leaf`<br>`GET /export/bundle/:id` | [`data/fixtures/api/blocks.json`](../data/fixtures/api/blocks.json)<br>[`data/fixtures/api/records_block_1.json`](../data/fixtures/api/records_block_1.json)<br>[`data/fixtures/api/prove_501.json`](../data/fixtures/api/prove_501.json)<br>[`data/fixtures/api/prove_live.json`](../data/fixtures/api/prove_live.json) |
| **#15 Parser & Integrity Management** | `GET /parsers`<br>`POST /parsers/test`<br>`POST /onboard`<br>`POST /tamper/drill`<br>`GET /system` | [`data/fixtures/api/parsers.json`](../data/fixtures/api/parsers.json)<br>[`data/fixtures/api/parsers_test.json`](../data/fixtures/api/parsers_test.json)<br>[`data/fixtures/api/onboard_preview.json`](../data/fixtures/api/onboard_preview.json)<br>[`data/fixtures/api/system.json`](../data/fixtures/api/system.json) |

---

## 3. Endpoints Specification

### 3.1 `GET /metrics` — Live Telemetry & Mix
Polled periodically (e.g., every 1 second) by the **#13 Analyst Dashboard**.

- **Method**: `GET`
- **Path**: `/metrics`
- **Response `200 OK`**:

Every value below is measured. **A field that could not be measured is
`null`** — never `0`, and never a placeholder constant. Note that `0` and
`null` mean different things: `0` is traffic observed at a genuinely zero
rate, `null` is nothing measured.

`ulpf serve` and `ulpf ingest` are separate processes, so the live gauges
(EPS, latency, LRU, queue) cannot be read straight from the ingest task
graph. The ingest process publishes them to a telemetry sidecar written next
to the ledger (`data/live_telemetry.json`, atomic write-then-rename) and this
plane reads it. `telemetry_state` names the three cases explicitly:

| `telemetry_state` | Meaning |
| :--- | :--- |
| `LIVE` | Fresh snapshot from a running ingest process |
| `STALE` | A snapshot exists but is older than the staleness bound, or its writer exited |
| `ABSENT` | Ingest has never run; there is nothing to report |

A stale or absent snapshot reports `null` for the live gauges rather than
serving an old reading as though it were current. A number that quietly
stopped moving is worse than no number.

```json
{
  "eps": null,
  "latency_p50_micros": null,
  "latency_p99_micros": null,
  "latency_samples": 0,
  "lru_hit_rate": null,
  "lru_lookups": null,
  "queue_depth": null,
  "queue_capacity": null,
  "dropped_count": null,
  "total_ingested": 50000,
  "total_parsed": null,
  "total_blocks": 50,
  "total_anomalies": null,
  "vendor_mix": {},
  "disposition_breakdown": {
    "Blocked": 264,
    "Allowed": 1115,
    "Dropped": 196,
    "Unknown": 425
  },
  "disposition_sampled": 2000,
  "telemetry_state": "ABSENT",
  "telemetry_age_ms": null,
  "disposition_source": "persisted_parquet_sample",
  "status": "UNKNOWN"
}
```

Field notes:

- **`vendor_mix`** holds per-vendor **counts**, not percentages. A percentage
  with no stated base is exactly the kind of number that misleads. An empty
  object means no vendor has been parsed by the running ingest process; it is
  never back-filled with a placeholder distribution.
- **`disposition_breakdown`** is computed over a bounded sample of the
  persisted Parquet corpus. `disposition_sampled` reports that sample size so
  the base is explicit. Only dispositions actually present appear.
- **`status`** is derived from real signals: `HEALTHY`/`DEGRADED` require live
  telemetry with a measured drop count, `IDLE` means the live pipeline stopped
  publishing, `UNKNOWN` means live telemetry is unavailable. It is never a
  constant, and a pipeline that has never been measured is deliberately **not**
  reported as healthy.
- **`latency_samples`** is published so the percentiles can be judged
  representative rather than taken on trust.

Fixtures are generated by running the real code, not hand-written:
`cargo run -p ulpf-cli --bin ulpf_fixture_gen` regenerates
`data/fixtures/api/metrics.json` and `alerts.json`.

- **Curl Example**:
```bash
curl -s http://localhost:8080/metrics | jq .
```

---

### 3.2 `GET /alerts` — Security & Forensic Alerts Feed
Returns active security alarms derived from real events — currently tamper
detections from verifying a Parquet block against the Merkle ledger.

**The feed is empty when nothing has actually happened.** It is never
populated with synthetic entries to make a demo look busy. Earlier revisions
of this contract documented two unconditional entries (`new_template_drift`,
`rare_cluster_surge`) that the server appended on every start regardless of
whether the system had seen any traffic; those were removed rather than
re-stated here. Parser-drift and surge alerts are emitted by the running
ingest process while traffic flows, not by the serve plane at rest.

- **Method**: `GET`
- **Path**: `/alerts`
- **Response `200 OK`**:
```json
[
  {
    "id": "01a0ec40-fccb-759c-80a9-dd4b9ac10787",
    "alert_type": "tamper_alarm",
    "severity": "Critical",
    "timestamp": 1790670077131,
    "title": "Forensic Tamper Alarm in Block #00000",
    "details": "Corrupted record at leaf 0: calculated SHA-256 10f90610737d6556 does not match stored hash.",
    "block_id": 0,
    "leaf_index": 0
  }
]
```

- **Severity Colors**:
  - `Critical` / `High`: Red alert badge
  - `Medium`: Yellow/Orange warning badge
  - `Low` / `Info`: Blue informational badge

---

### 3.3 `GET /blocks` — Archived Parquet Blocks & Ledger
Lists all blocks recorded in the append-only ledger with their RFC 6962 Merkle roots and integrity statuses.

- **Method**: `GET`
- **Path**: `/blocks`
- **Response `200 OK`**:
```json
[
  {
    "block_id": 0,
    "timestamp": 1789984478063,
    "leaf_count": 1000,
    "merkle_root": "e12dfacf15b6cc84fcedf91aeb3119f7d8c7a638e2c7e9541b9bb02d12833b72",
    "parquet_file": "block_00000.parquet",
    "status": "FAIL",
    "size_bytes": 345163,
    "file_exists": true
  },
  {
    "block_id": 1,
    "timestamp": 1789984478081,
    "leaf_count": 1000,
    "merkle_root": "398e59a6304ea9fa83b3d9eb5f0739bf081a01ce4d34e30e5c320040fd9e69a8",
    "parquet_file": "block_00001.parquet",
    "status": "PASS",
    "size_bytes": 425310,
    "file_exists": true
  }
]
```
- **Status values**: `PASS` (verified against ledger), `FAIL` (tampering detected), `FILE_MISSING`, `UNAUDITED`.

---

### 3.4 `GET /blocks/:id/records` — Raw vs OCSF Split View & Search
Allows SQL-like searching, filtering, and paging over columnar Parquet logs without DuckDB.

- **Method**: `GET`
- **Path**: `/blocks/{id}/records`
- **Query Parameters**:
  - `offset` *(integer, default: 0)*
  - `limit` *(integer, default: 50, max: 500)*
  - `vendor` *(string, optional: e.g. `cisco_asa`)*
  - `disposition` *(string, optional: `Allowed`, `Blocked`, `Dropped`)*
  - `ip` *(string, optional: search IP in raw log)*
  - `query` *(string, optional: text search over raw log, event ID, or hash)*
- **Response `200 OK`**:
```json
{
  "block_id": 1,
  "total_records_in_block": 1000,
  "filtered_records_count": 1000,
  "offset": 0,
  "limit": 50,
  "records": [
    {
      "event_id": "0195d2c2-84b2-7c3a-9e12-4211832049b0",
      "block_id": 1,
      "leaf_index": 0,
      "timestamp": 1789984478081,
      "vendor": "cisco_asa",
      "raw_log": "<166>Sep 21 14:00:01 asa-core-fw %ASA-6-302013: Built outbound TCP connection 1000672 for outside:203.0.113.54/25 to inside:10.1.6.180/52369",
      "raw_hash": "23dfa4b126307137f68c7849cb16b9b329ad4148e6587c6778dc651f158db49f",
      "ocsf": {
        "activity_id": 1,
        "activity_name": "Open",
        "category_uid": 4,
        "class_uid": 4001,
        "type_uid": 400101,
        "disposition": "Allowed",
        "time": 1789984478081,
        "src_endpoint": {
          "ip": "203.0.113.54",
          "port": 25,
          "interface": "outside"
        },
        "dst_endpoint": {
          "ip": "10.1.6.180",
          "port": 52369,
          "interface": "inside"
        },
        "connection_info": {
          "protocol_name": "TCP",
          "protocol_num": 6,
          "direction": "Outbound"
        },
        "metadata": {
          "product": {
            "vendor_name": "Cisco",
            "name": "ASA"
          },
          "version": "1.3.0"
        }
      }
    }
  ]
}
```

---

### 3.5 `GET /prove/:block/:leaf` — Merkle Inclusion Proof
Generates the cryptographic RFC 6962 audit path proving that a specific raw log was batched into the block Merkle root.

> [!NOTE]
> **#5 Complete — Ledger-Anchored Proofs**: Since `[integrity/M] Ledger fsync + prove/consistency CLI (#5)`, the `?live=true` path rebuilds the RFC 6962 tree and verifies the audit path against the **ledger-anchored root** (previously it verified against the just-recomputed tree root, which was trivially true). The bare default still returns `501 Not Implemented` — full production-grade proof verification UI workflows are scheduled for Issue #14. Frontend teams must handle `501` gracefully.

- **Method**: `GET`
- **Path**: `/prove/{block}/{leaf}`
- **Query Parameters**:
  - `live` *(boolean, optional)*: Pass `?live=true` to calculate live mathematical inclusion proof.
- **Default Behavior (Criteria of Issue #12)**:
  Returns HTTP `501 Not Implemented` with a structured payload:
```json
{
  "error": "Not Implemented",
  "code": 501,
  "message": "Merkle inclusion proof endpoint defaults to 501; ledger-anchored proofs landed in #5. Pass '?live=true' to execute live RFC 6962 audit path computation.",
  "block_id": 1,
  "leaf_index": 0
}
```
- **When `?live=true` is passed (`200 OK`)**:
```json
{
  "block_id": 1,
  "leaf_index": 0,
  "tree_size": 1000,
  "leaf_hash": "bf242bcb35880d5a0c9fbbb8b3df79732672c6d1fdfdfbab75c01f5981317e9e",
  "calculated_merkle_root": "398e59a6304ea9fa83b3d9eb5f0739bf081a01ce4d34e30e5c320040fd9e69a8",
  "ledger_merkle_root": "398e59a6304ea9fa83b3d9eb5f0739bf081a01ce4d34e30e5c320040fd9e69a8",
  "verified": true,
  "audit_path": [
    {
      "hash": "b5a92d4e8c3f1a2b0c4e5d6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c",
      "side": "Right"
    },
    {
      "hash": "c6b03e5f9d4a2b1c0d5e6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d",
      "side": "Right"
    }
  ],
  "standard": "RFC 6962 Certificate Transparency Standard"
}
```

---

### 3.6 `GET /export/bundle/:id` — Courtroom Evidence Bundle Export
Generates a downloadable `.tar.gz` bundle for legal courtroom handoff.

- **Method**: `GET`
- **Path**: `/export/bundle/{id}`
- **Response Headers**:
  - `Content-Type: application/gzip`
  - `Content-Disposition: attachment; filename="ulpf_evidence_block_00001.tar.gz"`
- **Contents of Exported Archive**:
  1. `README.txt`: Courtroom verification instructions and audit protocol.
  2. `block_{id:05}.parquet`: Real columnar Parquet block.
  3. `ledger_entry.json`: The anchored ledger line.
  4. `SHA256SUMS`: Hash manifest across all artifacts.

---

### 3.7 `GET /parsers` — Registered Parsers List
Lists built-in native extractors and dynamically onboarded parsers.

- **Method**: `GET`
- **Path**: `/parsers`
- **Response `200 OK`**:
```json
[
  {
    "vendor": "cisco_asa",
    "device_model": "ASA 5500-X / Firepower",
    "parser_type": "native_extractor",
    "status": "active",
    "confidence_score": 1.0
  },
  {
    "vendor": "fortigate",
    "device_model": "FortiGate NGFW (v7.0+)",
    "parser_type": "native_extractor",
    "status": "active",
    "confidence_score": 1.0
  }
]
```

---

### 3.8 `POST /parsers/test` — Dry-Run Single Line Test
Tests an arbitrary raw log line against an existing parser or a custom regex pattern without modifying disk.

- **Method**: `POST`
- **Path**: `/parsers/test`
- **Request Body**:
```json
{
  "raw_log": "<166>Sep 21 14:00:01 asa-core-fw %ASA-6-302013: Built outbound TCP connection 1000672 for outside:203.0.113.54/25 to inside:10.1.6.180/52369",
  "vendor": "cisco_asa"
}
```
- **Response `200 OK`**:
```json
{
  "matched": true,
  "vendor": "cisco_asa",
  "parsed_ocsf": {
    "activity_id": 1,
    "activity_name": "Open",
    "disposition": "Allowed",
    "src_endpoint": { "ip": "203.0.113.54", "port": 25 },
    "dst_endpoint": { "ip": "10.1.6.180", "port": 52369 }
  },
  "parse_duration_micros": 2.1,
  "raw_hash": "23dfa4b126307137f68c7849cb16b9b329ad4148e6587c6778dc651f158db49f",
  "protocol_detected": "HTTP/1.1 (TCP)",
  "notes": "Parsed through dynamic registry / universal baseline (read-only)"
}
```

---

### 3.9 `POST /onboard` — 1-Click Air-Gapped Onboarding Wizard
Synthesizes a new regex parser definition from 3–5 sample lines.

- **Method**: `POST`
- **Path**: `/onboard`
- **Safety Rule**: If `confirm` is `false`, **no files are written** (preview mode). If `confirm` is `true`, writes `.json` and `.yaml` to `data/parsers/` and registers into active memory.
- **Request Body**:
```json
{
  "vendor": "juniper_srx",
  "device_model": "srx-340",
  "sample_lines": [
    "RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.168.10.55/49152->10.0.0.1/443 None None 6 sample-policy trust untrust 12345 N/A(N/A) ge-0/0/0.0",
    "RT_FLOW: RT_FLOW_SESSION_CLOSE: session closed TCP FIN: 192.168.10.55/49152->10.0.0.1/443 None None 6 sample-policy trust untrust 12345 540(3200) 12(8) 15 UNKNOWN N/A(N/A) ge-0/0/0.0",
    "RT_FLOW: RT_FLOW_SESSION_DENY: session denied 192.168.20.100/53211->172.16.0.5/22 None None 6 block-ssh untrust dmz 12346 N/A(N/A) ge-0/0/1.0"
  ],
  "confirm": false
}
```
- **Preview Response (`200 OK`)**:
```json
{
  "status": "preview",
  "persisted": false,
  "vendor": "juniper_srx",
  "device_model": "srx-340",
  "parser_definition": {
    "vendor": "juniper_srx",
    "device_model": "srx-340",
    "regex_pattern": "^RT_FLOW:\\s+(?P<event_type>\\S+)...",
    "action_mappings": { "created": "Allowed", "denied": "Blocked" },
    "confidence_score": 1.0
  },
  "validation_report": {
    "passed": true,
    "total_samples": 3,
    "matched_samples": 3,
    "match_percentage": 100.0,
    "errors": []
  },
  "message": "Parser synthesized successfully (Preview mode: confirm=false, no files written)."
}
```
- **Hot-Loaded Response (`201 Created` with `confirm: true`)**:
```json
{
  "status": "hot_loaded",
  "persisted": true,
  "vendor": "juniper_srx",
  "device_model": "srx-340",
  "json_path": "data/parsers/juniper_srx.json",
  "yaml_path": "data/parsers/juniper_srx.yaml",
  "message": "Parser hot-loaded into active memory and written to disk."
}
```

---

### 3.10 `POST /tamper/drill` — Safe Adversarial Simulation
Executes a tamper drill to test forensic integrity alarms.

- **Method**: `POST`
- **Path**: `/tamper/drill`
- **Safety Rule**: **Never modifies real evidence.** Clones the target block into `data/scratch/tamper_drill_block_XXXXX.parquet` and corrupts only the copy.
- **Request Body**:
```json
{
  "block_id": 1,
  "leaf_index": 0,
  "spoofed_ip": "10.99.99.99",
  "confirm": true
}
```
- **Response `200 OK`**:
```json
{
  "status": "tamper_detected",
  "executed": true,
  "target_block_id": 1,
  "target_leaf_index": 0,
  "spoofed_ip": "10.99.99.99",
  "source_evidence_path": "data/parquet/block_00001.parquet",
  "scratch_drill_path": "data/scratch/tamper_drill_block_00001.parquet",
  "original_evidence_unmodified": true,
  "message": "Tamper Drill executed on cloned scratch copy. Original evidence remained 100% untouched. Red integrity alarm generated."
}
```

---

### 3.11 `GET /system` — System Settings & Scorecard
Displays batcher thresholds, queue capacity, and comparative benchmark metrics.

- **Method**: `GET`
- **Path**: `/system`
- **Response `200 OK`**:
```json
{
  "service_name": "ULPF Air-Gapped Forensic Backend",
  "version": "0.1.0",
  "air_gapped": true,
  "uptime_secs": 3600,
  "batcher": {
    "max_batch_size": 1000,
    "max_batch_duration_ms": 2000,
    "storage_dir": "data/parquet",
    "ledger_path": "data/ledger.jsonl",
    "compression": "Snappy (Lossless Columnar Parquet)"
  },
  "ingest_queue_capacity": 50000,
  "ingest_queue_depth": 0,
  "dynamic_parsers_loaded": 0,
  "total_archived_blocks": 25
}
```

---

## 4. Error Response Schema
All non-2xx responses return a consistent error body:
```json
{
  "error": "Error Category",
  "code": 404,
  "message": "Human readable explanation of the failure.",
  "block_id": 1,
  "leaf_index": 0
}
```
Standard status codes used:
- `400 Bad Request`: Missing or invalid input.
- `404 Not Found`: Block or file does not exist.
- `422 Unprocessable Entity`: Parser synthesis failed (e.g. unrecognizable pattern).
- `501 Not Implemented`: Endpoint stubbed pending prerequisite issue (e.g. proof CLI).
- `500 Internal Server Error`: Disk or compression failure.
