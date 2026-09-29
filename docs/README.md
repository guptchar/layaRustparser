# ULPF Docs — Start Here

| Doc | What it is |
| :--- | :--- |
| [`SRS.md`](SRS.md) | **Canonical** NTRO (a)–(k) traceability: design, code, test, measured row, honest verdict per requirement. |
| [`ARCHITECTURE_FINAL.md`](ARCHITECTURE_FINAL.md) | Canonical architecture: original proposal → why it fails in practice → what we built. Read this first. |
| [`SCORECARDS.md`](SCORECARDS.md) | Metric rulers, per-corpus scorecards, latency spectrum, forensic guarantees. |
| [`CONTRACTS.md`](CONTRACTS.md) | Serve REST contract per endpoint + which mock fixture each page codes against. |
| [`openapi.yaml`](openapi.yaml) | Machine-readable version of the serve contract. |
| [`ONBOARDING_RUNBOOK.md`](ONBOARDING_RUNBOOK.md) | Operator how-to: new firewall → parsed output in 3 commands, worked example included. |
| [`DEMO.md`](DEMO.md) | 2-minute video script + terminal timeline. Run via `scripts/run_demo.sh`. |
| [`PRESENTATION.md`](PRESENTATION.md) | 5-slide technical pitch + deliverables checklist. |
| [`WHY_ULPF.md`](WHY_ULPF.md) | The problem, shipper comparison, vendor matrix, one real line end to end. |
| [`INGEST_LIMITS.md`](INGEST_LIMITS.md) | Measured socket capacity and backpressure: 50k EPS loss-free per socket, UDP kernel drops vs TCP backpressure, the 500k answer, burst repro recipe. |
| [`CONTINUING_WORK.md`](CONTINUING_WORK.md) | Research notes for in-flight issues: what the code does today, what was decided, why. |
| This file (`README.md`) | The full doc index. The short map lives in the root `README.md`. |

Benchmarks (`benchmarks/` — committed, regenerable with `ulpf evaluate`):

| Doc | What it is |
| :--- | :--- |
| [`benchmarks/eval_hardcore_report.md`](benchmarks/eval_hardcore_report.md) | Core-corpus scorecard both engines (1,720 lines). The regression baseline. |
| [`benchmarks/eval_full_report.md`](benchmarks/eval_full_report.md) | Full-scale scorecard (224,657 lines / 183 MB). |
| [`benchmarks/eval_adversarial_report.md`](benchmarks/eval_adversarial_report.md) | Deterministic fuzz scorecard (757 mutated lines). |
| [`benchmarks/eval_holdout_report.md`](benchmarks/eval_holdout_report.md) | Frozen holdout scorecard, run once at evaluation cutoff (unseen vendors). |
| [`benchmarks/eval_duel_report.md`](benchmarks/eval_duel_report.md) | Vanilla-vs-3-tier duel over probe, fuzz, BGL, Thunderbird rounds. |

Submission exports (`releases/` — frozen PDFs, print from the template named in each comment):

| Doc | What it is |
| :--- | :--- |
| [`releases/ULPF_Architecture_and_Benchmarks_Guide.pdf`](releases/ULPF_Architecture_and_Benchmarks_Guide.pdf) | Colour architecture + benchmarks guide. Source: `pdf_template.html`. |
| [`releases/ULPF_Evaluation_Dossier_BW.pdf`](releases/ULPF_Evaluation_Dossier_BW.pdf) | Monochrome evaluation dossier for printing. Source: `pdf_bw_template.html`. |
| [`releases/README.md`](releases/README.md) | One-line regeneration recipe (headless-Chrome print-to-PDF). |
| [`submission/CHECKLIST.md`](submission/CHECKLIST.md) | Submission checklist — every line done or owner + issue link. |

History (`archive/` — superseded, do not cite or implement from):

| Doc | What it is |
| :--- | :--- |
| [`archive/OVERHAUL_PLAN.md`](archive/OVERHAUL_PLAN.md) | P1–P10 execution log. Finished work, not a spec. |
| [`archive/ARCHITECTURE.md`](archive/ARCHITECTURE.md) | Stale 2-tier architecture spec. |
| [`archive/SIH_EVALUATION_DOSSIER.md`](archive/SIH_EVALUATION_DOSSIER.md) | Older requirement-by-requirement defense dossier. |
| [`archive/SIMPLIFIED_EXPLANATION_AND_BENCHMARKS.md`](archive/SIMPLIFIED_EXPLANATION_AND_BENCHMARKS.md) | Older plain-language guide + benchmark deep-dive. |
| [`reference/Ulpf-proposal.pdf`](reference/Ulpf-proposal.pdf) | Original proposal. Implementation overruled it where `ARCHITECTURE_FINAL.md` says so. |

Root docs (repo root):

| Doc | What it is |
| :--- | :--- |
| [`../README.md`](../README.md) | Operational guide: quickstart, usage, crate map, short doc map. |
| [`../AGENTS.md`](../AGENTS.md) | Agent handbook: invariants, verification gate, gotchas, extension recipes. |
| [`../CONTRIBUTING.md`](../CONTRIBUTING.md) | Team workflow: branches, gate, PR checklist. |
| [`../FULL_DATASET_RESULTS.md`](../FULL_DATASET_RESULTS.md) | 224,657-line end-to-end run: evals, live 186-block chain, onboarding, what we found wrong. |
| [`../futurescope.md`](../futurescope.md) | Measured future gaps, in priority order. Nothing speculative. |
| [`../remainingStuff.md`](../remainingStuff.md) | Retired pointer: open work lives in GitHub issues now. Do not extend. |

Data docs and fixtures:

| Doc | What it is |
| :--- | :--- |
| [`../data/fixtures/api/`](../data/fixtures/api/) | Sample mock JSON for the serve contract. Frontend codes and mirrors against these (`frontend/laya-frontend/src/lib/mock-data.ts`); `serve_tests.rs` instead spins the real router over `data/parquet` + `data/ledger.jsonl`. |
| [`../data/raw/duel/README.md`](../data/raw/duel/README.md) | Frozen duel inputs: probe, BGL_2k, Thunderbird_2k + ground-truth provenance. |

Diagrams (`diagrams/` — Graphviz `.dot` sources + rendered `.png`; regenerate with `dot -Tpng -Gdpi=144`).

Repo config (not user docs — listed so nothing is unindexed):

| File | What it is |
| :--- | :--- |
| [`../.github/workflows/ci.yml`](../.github/workflows/ci.yml) | CI: clippy, fmt, tests. |
| [`../.github/workflows/claim.yml`](../.github/workflows/claim.yml) | Issue-claim automation. |
| [`../.github/workflows/reviewer.yml`](../.github/workflows/reviewer.yml) | Reviewer automation. |
| [`../.github/ISSUE_TEMPLATE/bug.yml`](../.github/ISSUE_TEMPLATE/bug.yml) | Bug report form. |
| [`../.github/ISSUE_TEMPLATE/config.yml`](../.github/ISSUE_TEMPLATE/config.yml) | Issue template config. |
| [`../.github/ISSUE_TEMPLATE/task.yml`](../.github/ISSUE_TEMPLATE/task.yml) | Task form. |
| [`../.github/pull_request_template.md`](../.github/pull_request_template.md) | PR checklist. |
| [`../.github/dependabot.yml`](../.github/dependabot.yml) | Dependency updates. |
| [`../.coderabbit.yaml`](../.coderabbit.yaml) | Review-bot config. |
| [`../docker-compose.yml`](../docker-compose.yml) | Local services. |

Frontend docs (owned by the dashboard track; indexed here so nothing is unlisted):

| File | What it is |
| :--- | :--- |
| [`../frontend/laya-frontend/README.md`](../frontend/laya-frontend/README.md) | Frontend setup and workflow. |
| [`../frontend/laya-frontend/Frontend%20_AGENTS.md`](../frontend/laya-frontend/Frontend%20_AGENTS.md) | Frontend agent handbook. |
| [`../frontend/laya-frontend/Frontend_issue14.md`](../frontend/laya-frontend/Frontend_issue14.md) | Issue-14 work notes. |
| [`../frontend/laya-frontend/Frontend_isssue15.md`](../frontend/laya-frontend/Frontend_isssue15.md) | Issue-15 work notes. |
| [`../frontend/laya-frontend/design_page1.md`](../frontend/laya-frontend/design_page1.md) | Design notes, page 1. |
| [`../frontend/laya-frontend/design_page2.md`](../frontend/laya-frontend/design_page2.md) | Design notes, page 2. |
| [`../frontend/laya-frontend/design_page4.md`](../frontend/laya-frontend/design_page4.md) | Design notes, page 4. |

External reference:

- [DeepWiki](https://deepwiki.com/guptchar/layaRustparser) — auto-generated wiki mirror of this repo. In-repo docs are authoritative on any disagreement.

Conventions:

- Real CLI flags come from `ulpf --help`. If docs and `--help` disagree, `--help` wins.
- Run binaries from the repo root (defaults assume `data/raw`, `data/parquet`, `data/ledger.jsonl`).
- `evaluate` / `benchmark` need **release** builds for meaningful numbers.
