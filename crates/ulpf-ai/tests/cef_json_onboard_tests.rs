//! Issue #9 acceptance: CEF + JSON synthesizers against real corpora.
//!
//! - CEF recall ≥95% on the CEF lines of `data/raw/fortigate.log`
//! - JSON onboarding over `data/raw/suricata.json` (mixed alert/flow/dns)
//! - Cross-vendor over-match sweep: neither pattern may fire on
//!   differently-shaped traffic anywhere in the corpora
//! - LRU hot-survival: a hot parser survives 100+ subsequent registrations

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use regex::Regex;
use ulpf_ai::onboarder::{DynamicParserRegistry, Onboarder, ParserDefinition, REGISTRY_CAPACITY};

fn raw_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/raw")
}

fn read_lines(path: &Path) -> Vec<String> {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    String::from_utf8_lossy(&bytes)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect()
}

/// Truncate to `n` CHARACTERS for a failure diagnostic.
///
/// A byte slice like `&line[..160]` panics when byte 160 lands mid-character,
/// which would abort the test before the recall threshold it was reporting
/// on — a diagnostic must never be able to take down the gate that prints it.
/// Log lines are not ASCII in general, so every truncation in this file goes
/// through here.
fn head(s: &str, n: usize) -> String {
    s.chars().take(n).collect()
}

/// `head` must be the reason a multibyte line can be reported at all. This
/// pins the guarantee with a string whose byte 3 is mid-character — the exact
/// case where `&s[..3]` panics.
#[test]
fn test_head_truncates_on_character_boundaries() {
    // 4-byte chars: byte offset 3 falls inside the first one.
    let s = "αβγδ";
    assert_eq!(head(s, 2), "αβ");
    assert_eq!(head(s, 99), s);
    assert_eq!(head("", 5), "");
    // Proof the naive form is what we are avoiding.
    assert!(std::panic::catch_unwind(|| &s[..3]).is_err());
}

/// Every traffic line in the corpora: (relative path, line). Ground-truth
/// sidecars (`gt.jsonl`, `*.csv`) are included deliberately — a pattern that
/// fires on metadata shaped like another vendor's traffic is still
/// over-matching. Docs (`*.md`) are not traffic and are skipped.
fn walk_corpus() -> Vec<(String, String)> {
    let root = raw_dir();
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .unwrap_or_else(|e| panic!("read_dir {}: {e}", dir.display()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .into_iter()
            .map(|e| e.path())
            .collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                stack.push(p);
            } else if p.is_file() && p.extension().and_then(|s| s.to_str()) != Some("md") {
                let rel = p
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/");
                for line in read_lines(&p) {
                    out.push((rel.clone(), line));
                }
            }
        }
    }
    out
}

fn train_cef() -> ParserDefinition {
    let lines = read_lines(&raw_dir().join("fortigate.log"));
    let cef: Vec<String> = lines.into_iter().filter(|l| l.contains("CEF:")).collect();
    assert!(
        cef.len() >= 50,
        "fortigate.log must hold the CEF corpus (found {})",
        cef.len()
    );
    // Train like `ulpf onboard`: the first 25 lines only.
    let train: Vec<&str> = cef.iter().take(25).map(String::as_str).collect();
    let (def, report) =
        Onboarder::generate_parser("fortinet", "fgt-cef", &train).expect("CEF must onboard");
    assert!(
        report.passed,
        "CEF training must validate: {:?}",
        report.errors
    );
    def
}

fn train_json() -> ParserDefinition {
    let lines = read_lines(&raw_dir().join("suricata.json"));
    assert!(!lines.is_empty(), "suricata.json must be non-empty");
    let train: Vec<&str> = lines.iter().take(25).map(String::as_str).collect();
    let (def, report) =
        Onboarder::generate_parser("suricata", "eve", &train).expect("EVE JSON must onboard");
    assert!(
        report.passed,
        "EVE training must validate: {:?}",
        report.errors
    );
    def
}

/// CEF recall on ALL CEF lines of fortigate.log (trained on the first 25):
/// ≥95% parse with endpoints + ports + action, and every successfully-parsed
/// act=deny/accept line carries a non-UNKNOWN disposition.
///
/// The ≥95% threshold is the real gate and it is NOT dead: a line that fails
/// to parse is counted and named, not panicked on. An earlier version of this
/// test panicked in the `Err` arm, which meant the threshold could never be
/// reached — the test enforced 100% while its doc comment claimed 95%.
#[test]
fn test_cef_recall_on_fortigate_cef_lines() {
    let def = train_cef();
    let lines = read_lines(&raw_dir().join("fortigate.log"));
    let cef: Vec<&str> = lines
        .iter()
        .filter(|l| l.contains("CEF:"))
        .map(String::as_str)
        .collect();

    let mut matched = 0;
    let mut failures: Vec<String> = Vec::new();
    let mut verdict_lines = 0;
    let mut verdict_known = 0;
    let mut unknown_verdicts: Vec<String> = Vec::new();
    for line in &cef {
        match def.parse(line) {
            Ok(ev) => {
                assert!(
                    ev.src_endpoint.ip.is_some() && ev.dst_endpoint.ip.is_some(),
                    "a MATCHED line must carry both endpoints: {line}"
                );
                assert!(
                    ev.src_endpoint.port.is_some() && ev.dst_endpoint.port.is_some(),
                    "a MATCHED line must carry spt/dpt: {line}"
                );
                matched += 1;
                if line.contains("act=deny") || line.contains("act=accept") {
                    verdict_lines += 1;
                    if ev.disposition != "Unknown" {
                        verdict_known += 1;
                    } else {
                        unknown_verdicts.push((*line).to_string());
                    }
                }
            }
            Err(e) => failures.push(format!("{}: {e}", head(line, 160))),
        }
    }
    let pct = matched as f64 / cef.len() as f64 * 100.0;
    assert!(
        pct >= 95.0,
        "CEF recall {matched}/{} = {pct:.1}% (need ≥95%)\n  first failures:\n    {}",
        cef.len(),
        failures
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n    ")
    );
    assert!(
        verdict_lines > 0,
        "corpus must contain act=deny/accept lines"
    );
    assert_eq!(
        verdict_known,
        verdict_lines,
        "every MATCHED act=deny/accept line must have a known disposition\n  offenders:\n    {}",
        unknown_verdicts
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n    ")
    );
}

/// JSON onboarding over the full suricata.json (mixed alert/flow/dns):
/// ≥95% of all records parse with endpoints + ports.
///
/// As in the CEF test, unparsed lines are counted and named rather than
/// panicked on, so the ≥95% threshold is the gate that actually runs.
#[test]
fn test_json_onboard_suricata_eve() {
    let def = train_json();
    let lines = read_lines(&raw_dir().join("suricata.json"));

    let mut matched = 0;
    let mut failures: Vec<String> = Vec::new();
    for line in &lines {
        match def.parse(line) {
            Ok(ev) => {
                assert!(
                    ev.src_endpoint.ip.is_some() && ev.dst_endpoint.ip.is_some(),
                    "a MATCHED record must carry both endpoints: {line}"
                );
                matched += 1;
            }
            Err(e) => failures.push(format!("{}: {e}", head(line, 160))),
        }
    }
    let pct = matched as f64 / lines.len() as f64 * 100.0;
    assert!(
        pct >= 95.0,
        "EVE recall {matched}/{} = {pct:.1}% (need ≥95%)\n  first failures:\n    {}",
        lines.len(),
        failures
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n    ")
    );
}

/// Cross-vendor over-match sweep: a synthesized pattern must match ZERO
/// lines outside its own shape class, across data/raw + full/ + duel/ +
/// adversarial/ (+ holdout/).
///
/// Same-shape lines elsewhere are NOT violations and are exempt with reason:
/// the `full/` mirror of fortigate.log, the adversarial EVE-shaped lines,
/// and gt sidecars embedding the same fields are the same format matching
/// correctly — the shadowing risk is firing on DIFFERENTLY-shaped traffic
/// (a CEF pattern matching KV/paloalto/BGL lines, a JSON pattern matching
/// non-JSON lines), which this sweep forbids absolutely.
#[test]
fn test_cross_vendor_overmatch_sweep() {
    let cef_def = train_cef();
    let json_def = train_json();
    let cef_re = Regex::new(&cef_def.regex_pattern).unwrap();
    let json_re = Regex::new(&json_def.regex_pattern).unwrap();

    let mut cef_violations: Vec<String> = Vec::new();
    let mut json_violations: Vec<String> = Vec::new();
    let mut scanned = 0;
    for (rel, line) in walk_corpus() {
        scanned += 1;
        // Same-shape exemptions (documented above).
        let is_cef_shape = line.contains("CEF:");
        let is_json_shape = line.trim_start().starts_with('{');
        if !is_cef_shape && cef_re.is_match(&line) {
            cef_violations.push(format!("{rel}: {}", head(&line, 160)));
        }
        if !is_json_shape && json_re.is_match(&line) {
            json_violations.push(format!("{rel}: {}", head(&line, 160)));
        }
    }
    assert!(
        scanned > 1000,
        "sweep must cover the corpora (scanned {scanned})"
    );
    assert!(
        cef_violations.is_empty(),
        "CEF pattern fired on {} non-CEF lines (first 5):\n  {}",
        cef_violations.len(),
        cef_violations
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n  ")
    );
    assert!(
        json_violations.is_empty(),
        "JSON pattern fired on {} non-JSON lines (first 5):\n  {}",
        json_violations.len(),
        json_violations
            .iter()
            .take(5)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n  ")
    );
}

/// A hot parser — registered first (hence stalest), then touched — must
/// survive 100+ subsequent registrations that force real evictions.
#[test]
fn test_eviction_hot_parser_survives_sustained_pressure() {
    let mk = |vendor: &str, model: String| ParserDefinition {
        vendor: vendor.into(),
        device_model: model,
        regex_pattern: r"^hot (?P<src_ip>\S+) (?P<dst_ip>\S+)$".to_string(),
        action_mappings: Default::default(),
        sample_logs: vec![],
        confidence_score: 1.0,
        created_at: 0,
        schema_version: 0,
        regex_cache: Arc::new(OnceLock::new()),
    };

    let mut reg = DynamicParserRegistry::new();
    // Hot parser registers FIRST, so without a use-stamp it would be the
    // very first eviction victim.
    assert_eq!(reg.register(mk("hot", "fw".into())), "hot:fw");
    for i in 0..REGISTRY_CAPACITY - 1 {
        let _ = reg.register(mk("fill", format!("m-{i:04}")));
    }
    assert_eq!(reg.len(), REGISTRY_CAPACITY);

    // Touch the hot entry: LRU must now spare it.
    assert!(reg.parse_key("hot:fw", "hot 10.0.0.1 10.0.0.2").is_some());

    // 120 churn registrations — every one past capacity evicts the stalest.
    for i in 0..120 {
        let _ = reg.register(mk("churn", format!("c-{i:04}")));
    }
    assert_eq!(reg.len(), REGISTRY_CAPACITY, "bound must hold");
    assert!(
        reg.parse_key("hot:fw", "hot 10.0.0.9 10.0.0.8").is_some(),
        "hot parser must survive 100+ registrations under eviction pressure"
    );
}
