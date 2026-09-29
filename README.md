# Universal Log Pre-processing Framework (ULPF)

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.96-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-CI--gated-brightgreen.svg)](https://github.com/guptchar/layaRustparser/actions/workflows/ci.yml)
[![Schema](https://img.shields.io/badge/schema-OCSF%201.3-green.svg)](https://schema.ocsf.io/)
[![Integrity](https://img.shields.io/badge/integrity-RFC%206962%20Merkle-purple.svg)](https://datatracker.ietf.org/doc/html/rfc6962)
[![Air--Gap](https://img.shields.io/badge/deployment-100%25%20Air--Gapped-red.svg)](#air-gapped-deployment)
[![Size](https://img.shields.io/badge/binary-15.9%20MB%20%3C%2035%20MB%20req-green.svg)](#requirements-matrix)
[![Repo](https://img.shields.io/badge/github-guptchar%2FlayaRustparser-blue.svg)](https://github.com/guptchar/layaRustparser)
[![CI](https://github.com/guptchar/layaRustparser/actions/workflows/ci.yml/badge.svg)](https://github.com/guptchar/layaRustparser/actions/workflows/ci.yml)
[![DeepWiki](https://img.shields.io/badge/docs-DeepWiki-blue.svg)](https://deepwiki.com/guptchar/layaRustparser)

**Tier-1 LRU catches known signatures in microseconds. Tier-2 Drain clusters the unknown into templates. Tier-3 Laya triages the novel on a bounded ring that never blocks ingest. Every event lands in OCSF 1.3, every block in an RFC 6962 Merkle ledger, every raw byte preserved.**

3.84 µs per log. 1,003,273 events per second. 100% action inviolability. 4,312× template compression. 186/186 blocks verify PASS. Zero cloud. Zero data loss.

New here? Ask questions about the codebase in plain English on our [DeepWiki](https://deepwiki.com/guptchar/layaRustparser)

![ULPF end-to-end flow: raw syslog/JSON/CSV -> classify -> zero-copy parse -> OCSF 1.3 JSON -> Parquet WORM + verify, with SHA-256(raw) / UUIDv7 -> RFC 6962 Merkle root -> ledger.jsonl provenance branch](docs/diagrams/hero-flow.png)

**Key capabilities**

- **Zero-copy hot path.** p50 is **3.84 µs**/line on the core corpus, **6.15 µs** at 224k lines (**−96.4% / −94.2%** vs the frozen baseline), **1,003,273 EPS** at full scale (**1.01×** baseline — throughput parity, the win is latency).
- **3-tier decision pipeline.** Tier-1 signature LRU (8,192 entries), Tier-2 Drain template miner with security anchor tokens, Tier-3 Laya triage on a bounded ring that **never blocks ingest** (invariant #5).
- **Lossless provenance.** Raw bytes are stored byte-for-byte in `raw_log`, `raw_hash = SHA-256(raw)` checks out on **all 224,657** full-scale lines, and every event gets a UUIDv7 `event_id`.
- **RFC 6962 Merkle WORM.** The append-only `ledger.jsonl` roots every Parquet block. Flip one byte and `ulpf verify` exits **2**; the live run passed **186/186** blocks.
- **One schema out: OCSF 1.3.** `NetworkActivity` (class 4001) for **6 formats today** (Cisco ASA, FortiGate, PAN-OS, pfSense, Suricata, CEF; [matrix](docs/WHY_ULPF.md#format--vendor-support-matrix)).
- **Action inviolability enforced on anchor tokens.** `ALLOW`/`PERMIT`/`ACCEPT` can never land in the same template cluster as `DENY`/`DROP`/`BLOCK`/`REJECT`; corpus-wide disposition purity is measured strictly in the [duel report](docs/benchmarks/eval_duel_report.md).
- **Beats vanilla Drain 4–0.** The committed [duel](docs/benchmarks/eval_duel_report.md) runs both engines over probe, fuzzed, BGL and Thunderbird rounds; 3-tier wins grouping accuracy on **all four** (e.g. 98.41% vs 71.73% on fuzzed input).
- **4,312× template compression.** 224,657 lines collapse to **32** Drain templates (baseline: 137,986) with template accuracy still at 100% — a ready-made feature table for any SIEM/ML system.
- **Air-gapped for real.** Zero outbound calls, no telemetry, no model downloads. One **15.9 MB** release binary (requirement: < 35 MB), plus Docker.

Every accuracy number links to a timestamped report from `ulpf evaluate`, and every table regenerates with one command (see [Reproduce the proof](#reproduce-the-proof)).

## Headline results (fresh, 2026-09-28)

All figures measured on the same machine (Linux x86_64, rustc 1.96.0), release build, `--engine all --duration 3 --threads 16`, median of 3 runs per corpus in one cool-state session. Reports are committed; timestamps inside them prove freshness (core/adversarial/full re-measured 2026-09-28; holdout frozen 2026-09-24T09:41:32Z and deliberately not re-run).

| Corpus | Lines | Accuracy (VCA / GA / TA / MeanAcc / Disposition) | p50 Baseline → 3-Tier | Throughput Baseline → 3-Tier | Audit dump |
| :--- | ---: | :--- | :--- | :--- | :---: |
| **Core** (committed fixtures) | 1,720 | **100 / 100 / 100 / 100 / 100 %** | 106.18 → **3.84 µs** (−96.4%) | 790,662 → 763,813 EPS (0.97×) | **0** |
| **Full scale** (regenerable) | **224,657** | **100 / 100 / 100 / 100 / 100 %** | 106.67 → **6.15 µs** (−94.2%) | 995,247 → **1,003,273 EPS (1.01×)** | **0** |
| **Adversarial** (fuzzed) | 757 | 96.30 / 98.41 / **100** / 97.15 / 93.53 % | 105.47 → **4.29 µs** (−95.9%) | 827,260 → 742,672 EPS (0.90×) | 382 ¹ |
| **Holdout** (frozen, one-shot) | 200 | 40 ² / 100 / **100** / 80 / 0 ² % | 74.47 → **5.63 µs** (−92.4%) | 1,721,640 → 154,514 EPS (0.09×) ³ | — |

¹ All 382 are **ground-truth-side mutation damage** — the fuzzer intentionally rewrote IP/port bytes; both engines produce *identical* mismatch counts (1,512 wrong fields each), so the delta is zero. Details: [`eval_adversarial_report.md`](docs/benchmarks/eval_adversarial_report.md) §1b.
² Holdout vendors are intentionally unseen; the baseline recognises **0** — tiered recognises **40%** on structure alone and scores **320 GT fields correct vs baseline's 0**. Disposition is **0% on both engines by construction of the experiment**: the holdout's vendors have no extractor, so every event resolves to `Unknown` disposition (160/200 lines *do* carry labels — 102 Allowed / 58 Blocked — and both engines fail them all). Known gap; vendor expansion is the fix. Details: [`eval_holdout_report.md`](docs/benchmarks/eval_holdout_report.md) §1b–§3.
³ Holdout is a small (200-line) one-shot frozen audit — its throughput ratio is not a performance signal; latency percentiles there are (p50 −92.4%).

**Invariants held on every corpus, both engines:**

| Invariant | Result |
| :--- | :---: |
| **Action Inviolability** (`ALLOW`/`PERMIT`/`ACCEPT` never merges with `DENY`/`DROP`/`BLOCK`/`REJECT`) | **100% preserved** |
| **Lossless provenance** (`raw_hash == SHA-256(raw_log)`, byte-exact) | **100.00%** |
| **No panics** (`catch_unwind` around every parse) | **0 aborts / N lines** |
| **Sidecar ground truth, full scale** (5 field keys × 224,657 lines) | **1,000,000 correct · 0 wrong · 123,285 honest null** |
| **Live Merkle chain at scale** (live ingest run) | **186 / 186 blocks verify PASS** |

## Why ULPF

Traditional shippers fail three ways: the **context-switching wall** (interpreter-heavy pipelines collapse under attack traffic), the **"hash vault" forensic illusion** (per-row hashes prove nothing about the stream), and **proprietary schema lock-in**. ULPF answers with a Rust zero-copy hot path, RFC 6962 Merkle chaining (edit one byte anywhere → root breaks → `ulpf verify` exits 2), and OCSF 1.3 as the single output schema.

Full argument, shipper-by-shipper comparison, the [vendor support matrix](docs/WHY_ULPF.md#format--vendor-support-matrix) and one real line traced end to end: [`docs/WHY_ULPF.md`](docs/WHY_ULPF.md).

## Architecture

![ULPF 3-tier pipeline: UDP/TCP syslog into Tier-1 LRU, Tier-2 Drain miner, Tier-3 Laya engine, then zero-copy extractors -> OCSF 1.3 event -> batcher -> SHA-256 + UUIDv7 + Merkle leaf -> ledger.jsonl and Parquet WORM -> ulpf verify 0/1/2](docs/diagrams/three-tier-pipeline.png)

**From proposal to production.** The original proposal ([`Ulpf-proposal.pdf`](docs/reference/Ulpf-proposal.pdf)) sketched a Python stack — Redpanda queue, WASM parser plugins, an offline LLM for mask synthesis, ClickHouse lake. What shipped is leaner: air-gap and determinism killed the LLM (non-deterministic outputs break forensic reproducibility), the queue (in-memory buffering suffices at this scale), and the plugins (native Rust needs no sandbox). What survived: OCSF as the single schema, Drain as the clustering core, lossless raw retention:

![Theoretical proposal in red engineered into the shipped ULPF pipeline in green](docs/diagrams/proposal-vs-reality.png)

Subsystem-by-subsystem account: [`docs/ARCHITECTURE_FINAL.md`](docs/ARCHITECTURE_FINAL.md).

**Why two engines?** The frozen Aho-Corasick **baseline** (`UniversalParser`) is the control; the 3-tier pipeline runs on the same corpora and has to beat it on latency and accuracy at every scale (~1.0× EPS at 224k — parity on throughput, −94.2% on latency; small-corpus exception noted in [Honest limitations](#honest-limitations)). Every scorecard prints both columns side by side, so no number is graded against itself. Workspace map (5 crates): [`AGENTS.md`](AGENTS.md#crate-map). Metric rulers, per-corpus scorecards, latency spectrum and forensic guarantees: [`docs/SCORECARDS.md`](docs/SCORECARDS.md).

## Reproduce the proof

```bash
git clone git@github.com:guptchar/layaRustparser.git && cd layaRustparser
cargo build --release

# Accuracy scorecards — regenerates the non-frozen committed reports in ~90s
# (the holdout report is frozen at the evaluation cutoff and deliberately not re-runnable)
./target/release/ulpf evaluate --engine all --duration 3 --threads 16 --samples 10000 --out docs/benchmarks/eval_hardcore_report.md --corpus core --data-dir data/raw
./target/release/ulpf evaluate --engine all --duration 3 --threads 16 --samples 10000 --out docs/benchmarks/eval_adversarial_report.md --corpus adversarial --data-dir data/raw --audit-dump audit_adv_dump.jsonl

# Full scale (dataset regenerable byte-for-byte, seed 777):
python3 scripts/gen_adversarial.py --full 25000
./target/release/ulpf evaluate --engine all --duration 3 --threads 16 --samples 10000 --out docs/benchmarks/eval_full_report.md --corpus core --data-dir data/raw/full

# Integrity demo (exit 0 = valid, 2 = tampered; block_0 is the deliberate tamper)
./target/release/ulpf verify --file data/parquet/block_00001.parquet --ledger data/ledger.jsonl
./target/release/ulpf verify --file data/parquet/block_00000.parquet --ledger data/ledger.jsonl
```

### Verifying the binary-size claim

The **15.9 MB** figure quoted above is measured, not asserted. It was taken on
2026-09-29 with the toolchain pinned in `rust-toolchain.toml` and the release
profile in `Cargo.toml` (`lto = "thin"`, `codegen-units = 1`, `strip = true`):

```bash
cargo build --release -p ulpf-cli
stat -c%s target/release/ulpf   # 15,889,672 bytes = 15.9 MB (15.2 MiB)
```

Re-run that before quoting the number. The size dropped from 22.8 MB when the
release profile was tuned, which is exactly how the earlier 18.6 MB figure went
stale — a published number with no command next to it rots silently.

The **container image** is a separate number and is **not** measured. See the
requirements matrix (row k) and [#45](https://github.com/guptchar/layaRustparser/issues/45)
for why the current base image makes the < 35 MB target unreachable, and what
would have to change.

> `evaluate`/`benchmark` need **release** builds on an idle machine: accuracy rows are deterministic, timing rows swing with load — hence the report timestamps. Exit codes: **0 valid · 1 IO error · 2 tamper**; console transcript in [`docs/SCORECARDS.md`](docs/SCORECARDS.md#cryptographic-chain-of-custody).

## Testing & verification gate

CI ([`ci.yml`](.github/workflows/ci.yml), plus [`claim.yml`](.github/workflows/claim.yml) / [`reviewer.yml`](.github/workflows/reviewer.yml) for issue/PR routing) runs the full gate on every PR and on every push that touches code — docs-only pushes (`**.md`, `**.png`, `**.dot`, `docs/**`) skip via `paths-ignore`. The CI badge at the top is the live signal; run the same gate locally before every commit (CI is authoritative for mergeability):

```bash
cargo clippy --workspace --all-targets \
    -- -A clippy::too_many_arguments -A clippy::field_reassign_with_default -D warnings
cargo fmt --all -- --check
cargo test --workspace --no-fail-fast
```

**Latest local run (2026-09-29): clippy 0 warnings · fmt clean · `253 passed · 1 failed · 1 ignored`.** The 1 failure is the known load-flaky micro-benchmark below (passes on idle re-run; CI skips it) — not a regression. Coverage: parser field accuracy + byte-exact SHA-256 per vendor, Drain anchor-token inviolability, the vanilla-vs-3-tier duel, tier behaviour, Merkle/tamper/exit-code contracts, CLI smoke tests, evaluator GT grading, air-gapped onboarder. The single `ignored` test is the frozen holdout (`test_holdout_novelty_end_to_end_at_freeze` in `crates/ulpf-ai/tests/ai_tests.rs`, ignored at the evaluation freeze) — run once at freeze via `cargo test -p ulpf-ai -- --ignored test_holdout`. The load-sensitive micro-benchmark (`test_classification_sub_microsecond_benchmark`, asserts < 2 µs/classification in a debug build) is **CI-skipped, not ignored** (`--skip` in `ci.yml`) and flakes on busy machines — re-run before assuming breakage ([`AGENTS.md`](AGENTS.md) Gotchas). For a fresh count: `cargo test --workspace --no-fail-fast`.

## Requirements matrix

| # | Requirement (verbatim from [`docs/archive/SIH_EVALUATION_DOSSIER.md`](docs/archive/SIH_EVALUATION_DOSSIER.md)) | Status | Evidence |
| :--- | :--- | :---: | :--- |
| a | Preserve complete raw event data without information loss | yes | `raw_log` byte-exact + `raw_hash == SHA-256(raw)` on **all 224,657** full-scale lines |
| b | Extract and parse source-specific attributes | yes | zero-copy extractors (ASA/FortiGate/PAN-OS/pfSense/Suricata/CEF) — **mean field accuracy 100%** on core & full ([rulers](docs/SCORECARDS.md#how-every-metric-is-measured-the-rulers)) |
| c | Normalize fields into a common event taxonomy | yes | OCSF 1.3 `NetworkActivity` 4001 — **VCA 100%** on core + full; **96.30%** on adversarial fuzz (mutated prefixes, baseline parity) |
| d | Maintain traceability between normalized and original events | yes | UUIDv7 `event_id` + SHA-256 digest on every event; `inspect` demo (quick start 6) |
| e | Plug-and-play onboarding of new log sources | yes | `ulpf onboard` — 3–5 sample lines → validated parser spec, zero network (quick start 7, full procedure: [`docs/ONBOARDING_RUNBOOK.md`](docs/ONBOARDING_RUNBOOK.md)) |
| f | Unified visibility across enterprise environments | yes | 5 vendor families → uniform OCSF JSON + Parquet schema ([data locations](#data-locations--programmatic-access)) |
| g | Efficient SIEM and Data Lake integration | yes | Parquet WORM blocks, queryable via DuckDB/pandas ([snippet](#data-locations--programmatic-access)) |
| h | AI/ML-ready security and operational analytics | yes | **32 Drain templates from 224,657 lines (4,312× compression)** — pre-clustered feature IDs ([scorecards](docs/SCORECARDS.md)) |
| i | Reduced parser development effort | yes | sample file → parser spec in **ms**, not days (quick start 7, [`docs/ONBOARDING_RUNBOOK.md`](docs/ONBOARDING_RUNBOOK.md)) |
| j | Deployable in an air-gapped network | yes | single binary with **zero** outbound calls anywhere in the runtime path. Dynamically linked against glibc (`libc`, `libm`, `libgcc_s`) — not a static build; a fully static musl build is not implemented ([#45](https://github.com/guptchar/layaRustparser/issues/45)) |
| k | Packaged in a container for platform independence (target < 35 MB) | partial | binary **15.9 MB measured**, inside the 35 MB target; **image size is not measured and is known to be over target** — the current `debian:bookworm-slim` base alone exceeds 35 MB before any of our code. Reaching the target needs a static musl build on `distroless/static`; see [#45](https://github.com/guptchar/layaRustparser/issues/45) for the size budget |

Canonical verdicts with design, code, tests, and measured rows: [`docs/SRS.md`](docs/SRS.md). (The older tables in [`docs/archive/SIH_EVALUATION_DOSSIER.md`](docs/archive/SIH_EVALUATION_DOSSIER.md) §4 and [`docs/ARCHITECTURE_FINAL.md`](docs/ARCHITECTURE_FINAL.md) §4 are superseded/corrected to match it.)

## Air-gapped deployment

```bash
docker build -t ulpf .
# or
docker compose up -d        # publishes 5140/udp + 5140/tcp, mounts ./data
```

- [`Dockerfile`](Dockerfile): multi-stage build → slim runtime, binaries at `/usr/local/bin`, no network calls at any point in the runtime path.
- [`docker-compose.yml`](docker-compose.yml): isolated `ulpf-net` bridge, persistent `./data/parquet` + `./data/ledger.jsonl` mounts, `restart: unless-stopped`.
- Strictly air-gapped: **zero** outbound calls — no telemetry, no model downloads, no license checks.

## Quick start

After `cargo build --release`, one command gives the full picture — both engines over the committed corpus, one aligned box you can screenshot (throughput, latency deltas, accuracy audit, the vanilla-vs-3-tier duel, PASS/FAIL gates, plain-words verdict), plus `scorecard_report.md` (regenerable, not committed):

```bash
./target/release/ulpf scorecard
```

Full walkthrough:

```bash
# 1. Build (rustc 1.96, edition 2021, stable toolchain)
cargo build --release

# 2. Run the accuracy evaluator — every metric in one Markdown report
./target/release/ulpf evaluate --engine all --duration 3 --threads 16 --samples 10000 --out report.md --corpus core --data-dir data/raw

# 3. Live ingest: start the engine (UDP+TCP on 5140, batch 1000 / 2000ms)
./target/release/ulpf ingest --udp 0.0.0.0:5140 --tcp 0.0.0.0:5140 --parquet-dir data/parquet --ledger data/ledger.jsonl

# 4. In another terminal: blast it with 5 vendors of synthetic traffic
./target/release/ulpf-generator -t 127.0.0.1:5140 -p udp -r 50000 -d 10 -D all

# 5. Verify the Merkle chain (exit 0 = PASS, 2 = tampered)
./target/release/ulpf verify --file data/parquet/block_00001.parquet --ledger data/ledger.jsonl

# 6. Inspect one forensic record (UUIDv7, raw bytes, OCSF output)
./target/release/ulpf inspect --file data/parquet/block_00001.parquet --count 1

# 7. Air-gapped onboarding of an unseen format (3–5 sample lines, no internet)
./target/release/ulpf onboard --sample sample_new_firewall.log --vendor juniper --model srx --out data/parsers
# Full operator procedure (collect samples → validate % → hot-load → verify): docs/ONBOARDING_RUNBOOK.md

# 8. End-to-end scripted demo (writes to scratch data/demo/, never touches fixtures)
bash scripts/run_demo.sh
```

## CLI reference

`ulpf --help` is authoritative; the summary below is transcribed from it.

| Subcommand | Purpose | Key flags (defaults) |
| :--- | :--- | :--- |
| `ingest` | Live Syslog UDP/TCP → OCSF → Merkle → Parquet | `--udp 0.0.0.0:5140` · `--tcp 0.0.0.0:5140` · `--parquet-dir data/parquet` · `--ledger data/ledger.jsonl` · `--batch-size 1000` · `--batch-timeout 2000` · `--reuse-port` |
| `verify` | Audit a Parquet block against the ledger | `--file <block.parquet>` · `--ledger data/ledger.jsonl` · **exit 0/1/2** |
| `onboard` | Synthesize + validate a parser from sample lines | `-s/--sample <file>` · `-v/--vendor <name>` · `-m/--model <name>` · `-o/--out data/parsers` |
| `benchmark` | Multi-core parse/normalize throughput | `--data-dir data/raw` *(long-only)* · `-d/--duration 5` · `-t/--threads 16` · `--compare` |
| `evaluate` | Baseline vs 3-Tier scorecard + percentiles + cache stats | `-e/--engine {all,baseline,tiered}` · `--corpus {core,adversarial,holdout}` · `--data-dir data/raw` · `-d/--duration 3` · `-t/--threads 16` · `-s/--samples 10000` · `-o/--out report.md` · `--json-out` · `--audit-dump` |
| `scorecard` | One-command side-by-side scorecard box: throughput, latency deltas, accuracy audit, vanilla-vs-3-tier duel, PASS/FAIL gates, verdict + markdown reports | `--corpus {core,adversarial,holdout}` · `--data-dir data/raw` · `-d/--duration 3` · `-t/--threads 16` · `-s/--samples 10000` · `-o/--out scorecard_report.md` |
| `inspect` | Print forensic records from a block | `-f/--file <block.parquet>` · `-c/--count 1` |
| `tamper` | Adversarial edit of a stored record (attack simulator) | `-f/--file <block.parquet>` · `-l/--leaf 0` · `-i/--ip 10.99.99.99` |

`ulpf-generator`: `-t/--target <IP:PORT>` · `-p/--proto {udp,tcp}` · `-r/--rate <EPS>` (0 = max) · `-d/--duration <sec>` (0 = infinite) · `-D/--dataset {all,cisco,fortigate,paloalto,suricata,pfsense,kaggle}` · `-w/--workers <N>` · `--data-dir <PATH>` (auto-located from cwd). Flags via `ulpf-generator --help`.

## Data locations & programmatic access

| Path | Contents |
| :--- | :--- |
| `data/raw/` — `*.log` + `suricata.json` (1,720 lines = the `core` corpus) | Cisco ASA (+VPN), FortiGate (+UTM), Palo Alto (+threat), pfSense (+IPv6), Suricata EVE — plus `kaggle_firewall.csv` (2,001 real-world rows, not in eval glob) |
| `data/raw/adversarial/` (757) · `data/raw/duel/` | Deterministic fuzz corpus + `gt.jsonl` sidecar; duel fixtures (probe + LogHub BGL/Thunderbird samples, attribution inside) |
| `data/raw/holdout/` (200) | **Frozen** unseen-vendor corpus + sidecar — never regenerate |
| `data/raw/full/` (224,657, gitignored) | Full-scale dataset: `python3 scripts/gen_adversarial.py --full 25000` (seed 777, md5-reproducible) |
| `data/parquet/block_*.parquet` · `data/ledger.jsonl` | WORM blocks (`block_00000` = tampered demo, `block_00001` = valid) · append-only Merkle roots |
| `data/parsers/` | Onboarder output (gitignored) |

**Programmatic access** — Parquet is a first-class analytics format: `duckdb -c "SELECT vendor, count(*) FROM 'data/parquet/*.parquet' GROUP BY vendor;"` or `pandas.read_parquet(...)`. Schema ([`ulpf-integrity/src/storage.rs`](crates/ulpf-integrity/src/storage.rs)): `event_id · block_id · leaf_index · timestamp · vendor · raw_log · raw_hash · ocsf_json`.

## Honest limitations

Known gaps, each one measured:

- **Adversarial GA: 98.41% vs baseline 100%** (−1.59 pt) — deny-class template variants cluster together on the fuzz corpus; Action Inviolability itself stays 100% (no ALLOW/DENY ever merges). Fix tracked as a stretch item (deny-class sub-clustering).
- **Corpus-wide mixed-action clusters on fuzzed lines (duel finding).** On R2, 10 of 81 clusters (vanilla: 17 of 53) still hold both dispositions: relay/CR-prefixed records keep a space, the tokenizer fuses the CSV/JSON into one token, and the buried action word never reaches the anchor vocabulary. The 100% inviolability gate is the bare-token canary; root cause and scope are disclosed in [`eval_duel_report.md`](docs/benchmarks/eval_duel_report.md) — deliberately **not tuned away** on the corpus that exposed it (a fix must be validated on unseen data).
- **Holdout disposition = 0/0** — the frozen holdout's vendors are *unseen* (no extractor exists for them), so both engines emit `Unknown` disposition on all 200 lines even though 160 carry ground-truth labels. It's an honest zero, not a skipped grade; vendor expansion is the fix.
- **Small-corpus throughput ratio ≈ 0.90–0.97×** — on 757–1,720 line corpora the tiered engine pays Drain bookkeeping that the pure baseline skips; at 224k lines throughput reaches parity (**1.01×**). The tiers' consistent win is **latency** (−92% to −96% p50 at every scale), not throughput.
- **Throughput/latency are load-sensitive** — same-code reruns swing baseline p50 between ~73 µs (idle) and ~1,104 µs (busy). Accuracy is deterministic; timing is not. Reports embed timestamps for this reason. The 2026-09-28 re-measure caught this live: one adversarial run halved baseline throughput (428,899 vs ~830k EPS), and one full-scale run doubled baseline p50 (196.49 vs ~107 µs) — median-of-3 absorbs both, which is why the ritual requires it.
- **Full-scale p50 (6.15 µs) is over the 5.0 µs latency gate.** The gate is calibrated on the core corpus, where p50 is 3.84 µs and passes. At 224,657 lines the working set no longer stays cache-resident (still −94.2% vs baseline). The gate stays where it is; the gap is tracked in the roadmap.
- **The 2026-09-25 full-scale 0.08× row (74,489 EPS) was a bad run, superseded 2026-09-28.** Re-running the identical 224,657-line dataset three times gave tiered 912,249 / 1,003,273 / 930,901 EPS (0.84 / 1.01 / 1.26×) — the old figure sits 12× below the lowest fresh run, and the 2026-09-24 session independently measured 1.05×. Likely cause: load-side collapse on the evaluator's tiered-throughput path, which funnels 16 threads through one shared `Arc<Mutex<DrainMiner>>` (production `ingest` gives each worker its own pipeline, so this ceiling is harness-specific). Details: [`FULL_DATASET_RESULTS.md`](FULL_DATASET_RESULTS.md) §2.
- **Live-ingest socket ceiling ≈ 50k EPS loss-free** (4 MiB `SO_RCVBUF`; the kernel default sheds from ~30k) — measured per transport with loss accounting and a burst repro recipe in [`docs/INGEST_LIMITS.md`](docs/INGEST_LIMITS.md); the evaluator's in-process numbers are the engine's own capacity.
- **Container image not yet < 35 MB** — the binary requirement is met and measured (15.9 MB). The image target is *not* met, and cannot be met with the current base: `debian:bookworm-slim` is roughly 74 MB on its own, so no amount of trimming our own layers brings the total under 35 MB. Getting there requires a fully static musl build on `distroless/static` and dropping the generator and fixture data from the runtime image — see [#45](https://github.com/guptchar/layaRustparser/issues/45). We have not measured an image size, so we are not quoting one.
- One test is load-flaky by design (`test_classification_sub_microsecond_benchmark`, CI-skipped via `--skip`, not ignored) — documented in [`AGENTS.md`](AGENTS.md).

## Documentation map

Full index: [`docs/README.md`](docs/README.md) (every doc, one row each). Short version:

| Document | What it gives you |
| :--- | :--- |
| [`docs/ARCHITECTURE_FINAL.md`](docs/ARCHITECTURE_FINAL.md) | Implemented system vs original proposal, subsystem by subsystem |
| [`docs/SCORECARDS.md`](docs/SCORECARDS.md) | Metric rulers, per-corpus scorecards, latency spectrum, forensic guarantees |
| [`docs/CONTRACTS.md`](docs/CONTRACTS.md) · [`docs/openapi.yaml`](docs/openapi.yaml) | Serve REST contract + mock fixtures · machine-readable version |
| [`docs/ONBOARDING_RUNBOOK.md`](docs/ONBOARDING_RUNBOOK.md) | New firewall → parsed output in 3 commands |
| [`docs/WHY_ULPF.md`](docs/WHY_ULPF.md) | The problem, shipper comparison, vendor support matrix, one real line end to end |
| [`docs/PRESENTATION.md`](docs/PRESENTATION.md) · [`docs/DEMO.md`](docs/DEMO.md) | 5-slide pitch script · 2-minute demo script · [printable PDFs in `docs/releases/`](docs/releases/) |
| [`docs/benchmarks/`](docs/benchmarks/) | Committed scorecards: `eval_hardcore_report.md` (core) · `eval_full_report.md` (224k) · `eval_adversarial_report.md` (fuzz) · `eval_holdout_report.md` (frozen) · `eval_duel_report.md` (vanilla-vs-3-tier) |
| [`FULL_DATASET_RESULTS.md`](FULL_DATASET_RESULTS.md) | 224,657-line end-to-end run: evals, live 186-block chain, onboarding, what we found wrong |
| [`futurescope.md`](futurescope.md) | Measured future gaps, in priority order |
| [`AGENTS.md`](AGENTS.md) · [`CONTRIBUTING.md`](CONTRIBUTING.md) | Contributor handbook · team workflow |
| [`data/fixtures/api/`](data/fixtures/api/) | Sample mock JSON for the serve contract |
| [`data/raw/duel/README.md`](data/raw/duel/README.md) | Frozen duel inputs + ground-truth provenance |
| [`docs/archive/`](docs/archive/) | Superseded, do not cite: [`OVERHAUL_PLAN.md`](docs/archive/OVERHAUL_PLAN.md) (P1–P10 log, not a spec) · [`ARCHITECTURE.md`](docs/archive/ARCHITECTURE.md) · [`SIH_EVALUATION_DOSSIER.md`](docs/archive/SIH_EVALUATION_DOSSIER.md) · [`SIMPLIFIED_EXPLANATION_AND_BENCHMARKS.md`](docs/archive/SIMPLIFIED_EXPLANATION_AND_BENCHMARKS.md) |
| [`docs/releases/`](docs/releases/) | Frozen submission PDFs: [`ULPF_Architecture_and_Benchmarks_Guide.pdf`](docs/releases/ULPF_Architecture_and_Benchmarks_Guide.pdf) · [`ULPF_Evaluation_Dossier_BW.pdf`](docs/releases/ULPF_Evaluation_Dossier_BW.pdf) · [`README.md`](docs/releases/README.md) (regen recipe) |
| [`docs/reference/Ulpf-proposal.pdf`](docs/reference/Ulpf-proposal.pdf) | Original proposal — overruled where `ARCHITECTURE_FINAL.md` says so |
| Repo config | CI and forms, each filed once in `docs/README.md`: [`.github/workflows/`](.github/workflows/) · [`.github/ISSUE_TEMPLATE/`](.github/ISSUE_TEMPLATE/) · [`pull_request_template.md`](.github/pull_request_template.md) · [`dependabot.yml`](.github/dependabot.yml) · [`.coderabbit.yaml`](.coderabbit.yaml) · [`docker-compose.yml`](docker-compose.yml) |
| Frontend notes | Dashboard-track docs, each filed once in `docs/README.md`: [`frontend/laya-frontend/README.md`](frontend/laya-frontend/README.md) and sibling notes |
| [`docs/diagrams/`](docs/diagrams/) | Graphviz `.dot` sources + rendered `.png` (regenerate with `dot -Tpng -Gdpi=144`) |
| [`scripts/run_demo.sh`](scripts/run_demo.sh) | One-command non-destructive demo |

## Project status & roadmap

**Done:** measurement-first ruler fixes → vendor extractors → CEF → parse-order/LRU tiers → audit null-correct rules → dynamic message-code anchors → GA/TA to 100 both engines → deterministic adversarial + frozen holdout corpora → sidecar ground truth → full-scale 224,657-line validation → 186-block live chain → CLI hardening → ASA verdict-phrase union → fresh re-run evidence → vanilla-vs-3-tier duel surfaced in `ulpf scorecard`.

**In progress:** universal wire formats (LEEF, generic KV/JSON/XML, RFC5424 SD) · vendor expansion (~10, ISRO-relevant) · multi-source measurement + Mapping-Coverage metric · container < 35 MB (planned) · submission artifacts (readme/pitch/video) · deny-class GA stretch (droppable).

**Performance gates** (checked whenever hot path/miner changes): p50 < 5.0 µs *(core-corpus: 3.84 µs passes; full-scale 6.15 µs is over the line, tracked above)* · LRU hit rate > 90% · Action Inviolability 100% · grouping accuracy > 90%.

## License

Apache-2.0 — see [`LICENSE`](LICENSE).
