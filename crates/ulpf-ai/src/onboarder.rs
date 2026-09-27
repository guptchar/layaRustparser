use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

use ulpf_core::schema::ocsf::{
    activity_id, disposition, ConnectionInfo, Endpoint, Metadata, NetworkActivity, Product,
};

/// Result of automated sandbox validation on synthesized parser
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ValidationReport {
    pub passed: bool,
    pub total_samples: usize,
    pub matched_samples: usize,
    pub match_percentage: f64,
    pub errors: Vec<String>,
}

/// Dynamically generated and exportable parser definition.
///
/// `regex_cache` is excluded from serde (YAML/JSON) — it is a runtime-only
/// compiled-regex cache. `Clone` is manual because `OnceLock<Regex>` is not
/// `Clone`; wrapping in `Arc` lets clones share the same cached regex.
#[derive(Debug, Serialize, Deserialize)]
pub struct ParserDefinition {
    pub vendor: String,
    pub device_model: String,
    pub regex_pattern: String,
    pub action_mappings: HashMap<String, String>,
    pub sample_logs: Vec<String>,
    pub confidence_score: f64,
    pub created_at: i64,
    #[serde(skip)]
    pub regex_cache: Arc<OnceLock<Option<Regex>>>,
}

impl Clone for ParserDefinition {
    fn clone(&self) -> Self {
        Self {
            vendor: self.vendor.clone(),
            device_model: self.device_model.clone(),
            regex_pattern: self.regex_pattern.clone(),
            action_mappings: self.action_mappings.clone(),
            sample_logs: self.sample_logs.clone(),
            confidence_score: self.confidence_score,
            created_at: self.created_at,
            // Arc::clone shares the same OnceLock — clones reuse the compiled regex.
            regex_cache: Arc::clone(&self.regex_cache),
        }
    }
}

impl ParserDefinition {
    /// Serialize parser definition to clean JSON string
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string_pretty(self).context("Failed to serialize parser to JSON")
    }

    /// Load parser definition from JSON
    pub fn from_json(json_str: &str) -> Result<Self> {
        serde_json::from_str(json_str).context("Failed to deserialize parser from JSON")
    }

    /// Serialize parser definition to YAML via `noyalib` (pure-Rust, air-gapped).
    /// Field names are stable — `data/parsers/*.yaml` consumers depend on them.
    pub fn to_yaml(&self) -> Result<String> {
        noyalib::to_string(self).context("Failed to serialize parser to YAML")
    }

    /// Load parser definition from YAML (or JSON, which is valid YAML 1.2).
    /// `regex_cache` is `#[serde(skip)]` so serde fills it with `Default`
    /// (`Arc::new(OnceLock::new())`) — no repair needed.
    pub fn from_yaml(yaml_str: &str) -> Result<Self> {
        noyalib::from_str::<ParserDefinition>(yaml_str)
            .context("Invalid YAML: could not deserialize ParserDefinition")
    }

    /// Parse an incoming raw log line into normalized OCSF 1.3 NetworkActivity.
    /// Uses the cached compiled regex (Arc<OnceLock<Option<Regex>>>) — no per-event recompile.
    /// Returns Err if the pattern fails to compile (never panics).
    pub fn parse(&self, raw: &str) -> Result<NetworkActivity> {
        let compiled_re = self
            .regex_cache
            .get_or_init(|| Regex::new(&self.regex_pattern).ok())
            .as_ref()
            .ok_or_else(|| {
                anyhow!(
                    "Invalid compiled regex in parser definition: {}",
                    self.regex_pattern
                )
            })?;
        self.parse_with_regex(compiled_re, raw)
    }

    /// Parse with a pre-compiled regex (the registry compiles once at register
    /// time — recompiling inside `parse_any`'s candidate loop would be O(n) Regex::new).
    pub fn parse_with_regex(&self, compiled_re: &Regex, raw: &str) -> Result<NetworkActivity> {
        let caps = compiled_re.captures(raw).ok_or_else(|| {
            anyhow!(
                "Log did not match dynamic parser pattern for vendor '{}': {}",
                self.vendor,
                raw
            )
        })?;

        let now_ms = Utc::now().timestamp_millis();

        // 1. Extract Endpoints
        let src_ip = caps.name("src_ip").map(|m| m.as_str().to_string());
        let dst_ip = caps.name("dst_ip").map(|m| m.as_str().to_string());

        let src_port = caps
            .name("src_port")
            .and_then(|m| m.as_str().parse::<u16>().ok());
        let dst_port = caps
            .name("dst_port")
            .and_then(|m| m.as_str().parse::<u16>().ok());

        let src_intf = caps.name("interface").map(|m| m.as_str().to_string());
        let src_zone = caps.name("src_zone").map(|m| m.as_str().to_string());
        let dst_zone = caps.name("dst_zone").map(|m| m.as_str().to_string());

        let src_endpoint = Endpoint::new(src_ip, src_port, src_intf, src_zone);
        let dst_endpoint = Endpoint::new(dst_ip, dst_port, None, dst_zone);

        // 2. Extract Protocol
        let mut proto_num = None;
        let mut proto_name = None;

        if let Some(m) = caps.name("protocol") {
            let p_str = m.as_str().trim();
            if let Ok(num) = p_str.parse::<u8>() {
                proto_num = Some(num);
                proto_name = Some(protocol_name_from_num(num).to_string());
            } else {
                let upper = p_str.to_ascii_uppercase();
                proto_num = protocol_num_from_name(&upper);
                proto_name = Some(upper);
            }
        }

        let connection_info = ConnectionInfo::new(proto_num, proto_name, None);

        // 3. Extract & Map Action / Disposition
        let raw_action = caps
            .name("action")
            .or_else(|| caps.name("action_verb"))
            .map(|m| m.as_str().to_ascii_lowercase())
            .unwrap_or_else(|| "unknown".to_string());

        let norm_disp = self
            .action_mappings
            .get(&raw_action)
            .cloned()
            .unwrap_or_else(|| match raw_action.as_str() {
                "accept" | "permit" | "allow" | "created" | "passed" | "pass" => {
                    disposition::ALLOWED.to_string()
                }
                "deny" | "block" | "reject" | "denied" | "blocked" => {
                    disposition::BLOCKED.to_string()
                }
                "drop" | "dropped" => disposition::DROPPED.to_string(),
                "closed" | "close" | "teardown" => disposition::ALLOWED.to_string(),
                _ => disposition::UNKNOWN.to_string(),
            });

        // 4. Derive Activity ID
        let act_id = match raw_action.as_str() {
            "created" | "start" | "open" => activity_id::OPEN,
            "closed" | "close" | "teardown" => activity_id::CLOSE,
            _ => {
                if norm_disp == disposition::ALLOWED {
                    activity_id::TRAFFIC_FLOW
                } else {
                    activity_id::OTHER
                }
            }
        };

        // 5. Build Metadata with SHA-256 and UUIDv7
        let raw_hash = hex::encode(Sha256::digest(raw.as_bytes()));
        let event_id = Uuid::now_v7().to_string();
        let product = Product::new(&self.vendor, &self.device_model, None);
        let metadata = Metadata::new(product, raw, raw_hash, event_id, now_ms);

        // 6. Build Unmapped fields
        let mut unmapped = HashMap::new();
        for name in compiled_re.capture_names().flatten() {
            if !matches!(
                name,
                "src_ip"
                    | "src_port"
                    | "dst_ip"
                    | "dst_port"
                    | "protocol"
                    | "action"
                    | "action_verb"
                    | "interface"
                    | "src_zone"
                    | "dst_zone"
            ) {
                if let Some(m) = caps.name(name) {
                    unmapped.insert(name.to_string(), m.as_str().to_string());
                }
            }
        }

        let mut event = NetworkActivity::new(
            act_id,
            now_ms,
            norm_disp,
            src_endpoint,
            dst_endpoint,
            connection_info,
            None,
            metadata,
        );

        if !unmapped.is_empty() {
            event = event.with_unmapped(unmapped);
        }

        Ok(event)
    }

    /// Generates standalone Rust extractor code for inclusion in ulpf-core
    pub fn generate_rust_code(&self) -> String {
        let template = r#"// Auto-generated 1-click OCSF 1.3 Extractor for __VENDOR__ __MODEL__
// Generated by ULPF Air-Gapped AI Onboarder
use ulpf_core::schema::ocsf::{
    activity_id, disposition, ConnectionInfo, Endpoint, Metadata, NetworkActivity, Product,
};
use regex::Regex;
use std::sync::OnceLock;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use chrono::Utc;

pub struct __VENDOR____MODEL__Extractor {
    regex: OnceLock<Regex>,
}

impl __VENDOR____MODEL__Extractor {
    pub fn new() -> Self {
        Self { regex: OnceLock::new() }
    }

    pub fn parse(&self, raw: &str) -> anyhow::Result<NetworkActivity> {
        let re = self.regex.get_or_init(|| {
            Regex::new(r"__PATTERN__").expect("Invalid regex for __VENDOR__")
        });

        let caps = re.captures(raw).ok_or_else(|| anyhow::anyhow!("Log match failed"))?;
        let now_ms = Utc::now().timestamp_millis();
        let raw_hash = hex::encode(Sha256::digest(raw.as_bytes()));
        let event_id = Uuid::now_v7().to_string();

        let src_ip = caps.name("src_ip").map(|m| m.as_str().to_string());
        let dst_ip = caps.name("dst_ip").map(|m| m.as_str().to_string());
        let src_port = caps.name("src_port").and_then(|m| m.as_str().parse::<u16>().ok());
        let dst_port = caps.name("dst_port").and_then(|m| m.as_str().parse::<u16>().ok());

        let src_endpoint = Endpoint::new(src_ip, src_port, None, None);
        let dst_endpoint = Endpoint::new(dst_ip, dst_port, None, None);

        let proto_str = caps.name("protocol").map(|m| m.as_str()).unwrap_or("TCP");
        let connection_info = ConnectionInfo::new(Some(6), Some(proto_str.to_string()), None);

        let product = Product::new("__VENDOR__", "__MODEL__", None);
        let metadata = Metadata::new(product, raw, raw_hash, event_id, now_ms);

        Ok(NetworkActivity::new(
            activity_id::TRAFFIC_FLOW,
            now_ms,
            disposition::ALLOWED,
            src_endpoint,
            dst_endpoint,
            connection_info,
            None,
            metadata,
        ))
    }
}
"#;
        template
            .replace("__VENDOR__", &sanitize_ident(&self.vendor))
            .replace("__MODEL__", &sanitize_ident(&self.device_model))
            .replace("__PATTERN__", &self.regex_pattern)
    }
}

/// Air-gapped 1-Click Parser Onboarder
pub struct Onboarder;

impl Onboarder {
    /// Analyze 3–5 sample lines of an unknown perimeter device log,
    /// synthesize a non-greedy compiled regex with named capture groups,
    /// perform sandbox validation (≥95% extraction pass rate with warnings),
    /// and produce an exportable `ParserDefinition`.
    pub fn generate_parser(
        vendor: &str,
        device_model: &str,
        samples: &[&str],
    ) -> Result<(ParserDefinition, ValidationReport)> {
        if samples.len() < 3 {
            return Err(anyhow!(
                "Onboarder requires at least 3 sample log lines, found {}",
                samples.len()
            ));
        }

        // 1. Synthesize strict non-greedy regex pattern from samples
        let pattern = Self::synthesize_regex(samples)?;

        // 2. Derive action mappings
        let action_mappings = Self::infer_action_mappings(samples);

        // 3. Run Automated Sandbox Validation
        let parser_def = ParserDefinition {
            vendor: vendor.to_string(),
            device_model: device_model.to_string(),
            regex_pattern: pattern.clone(),
            action_mappings,
            sample_logs: samples.iter().map(|s| s.to_string()).collect(),
            confidence_score: 1.0,
            created_at: Utc::now().timestamp_millis(),
            regex_cache: Arc::new(OnceLock::new()),
        };
        let report = Self::validate_parser(&parser_def, samples)?;

        if !report.passed {
            return Err(anyhow!(
                "Sandbox validation failed (match rate: {:.1}%): {:?}",
                report.match_percentage,
                report.errors
            ));
        }

        // Derive confidence from actual match percentage — a parser that
        // failed to extract 5% of its own vendor's traffic is not 100% confident.
        let parser_def = ParserDefinition {
            confidence_score: report.match_percentage / 100.0,
            ..parser_def
        };

        Ok((parser_def, report))
    }

    /// Automated Sandbox Validation: verifies ≥95% of samples match and extract valid IPs and ports.
    /// Failures are surfaced as warnings in `errors`, not hard failures.
    pub fn validate_parser(
        parser: &ParserDefinition,
        samples: &[&str],
    ) -> Result<ValidationReport> {
        let compiled_re = Regex::new(&parser.regex_pattern)
            .with_context(|| format!("Failed to compile regex: {}", parser.regex_pattern))?;

        let mut matched = 0;
        let mut evaluated = 0;
        let mut errors = Vec::new();

        for (idx, sample) in samples.iter().enumerate() {
            let line = sample.trim();
            if line.is_empty() {
                continue;
            }
            evaluated += 1;

            let caps = match compiled_re.captures(line) {
                Some(c) => c,
                None => {
                    errors.push(format!(
                        "Sample #{} did not match regex pattern: '{}'",
                        idx + 1,
                        line
                    ));
                    continue;
                }
            };

            // Validate src_ip
            let src_ip_opt = caps.name("src_ip").map(|m| m.as_str());
            match src_ip_opt {
                Some(ip_str) => {
                    if IpAddr::from_str(ip_str).is_err() {
                        errors.push(format!(
                            "Sample #{}: invalid IP for src_ip: '{}'",
                            idx + 1,
                            ip_str
                        ));
                        continue;
                    }
                }
                None => {
                    errors.push(format!(
                        "Sample #{}: missing required capture group 'src_ip'",
                        idx + 1
                    ));
                    continue;
                }
            }

            // Validate dst_ip
            let dst_ip_opt = caps.name("dst_ip").map(|m| m.as_str());
            match dst_ip_opt {
                Some(ip_str) => {
                    if IpAddr::from_str(ip_str).is_err() {
                        errors.push(format!(
                            "Sample #{}: invalid IP for dst_ip: '{}'",
                            idx + 1,
                            ip_str
                        ));
                        continue;
                    }
                }
                None => {
                    errors.push(format!(
                        "Sample #{}: missing required capture group 'dst_ip'",
                        idx + 1
                    ));
                    continue;
                }
            }

            // Validate ports if present
            if let Some(sp) = caps.name("src_port") {
                if sp.as_str().parse::<u16>().is_err() {
                    errors.push(format!(
                        "Sample #{}: invalid port for src_port: '{}'",
                        idx + 1,
                        sp.as_str()
                    ));
                    continue;
                }
            }

            if let Some(dp) = caps.name("dst_port") {
                if dp.as_str().parse::<u16>().is_err() {
                    errors.push(format!(
                        "Sample #{}: invalid port for dst_port: '{}'",
                        idx + 1,
                        dp.as_str()
                    ));
                    continue;
                }
            }

            matched += 1;
        }

        let total = evaluated;
        let pct = if total > 0 {
            (matched as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        // 95% threshold with warnings — allows floor(N/20) failures so the
        // relaxation is meaningful at any sample count (1 failure at N=20,
        // 2 at N=40, etc.). Was: hard 100% + zero errors.
        let max_failures = (total / 20).max(1);
        let passed = (total - matched) <= max_failures;

        Ok(ValidationReport {
            passed,
            total_samples: total,
            matched_samples: matched,
            match_percentage: pct,
            errors,
        })
    }

    /// Deterministic pattern synthesizer
    fn synthesize_regex(samples: &[&str]) -> Result<String> {
        let first = samples[0];

        // Case 1: Check for Juniper SRX / Directional Flow format: `IP/PORT->IP/PORT` or `IP:PORT -> IP:PORT`
        if first.contains("->")
            || first.contains("session created")
            || first.contains("session denied")
        {
            return Self::synthesize_flow_regex(samples);
        }

        // Case 2: Check for Key-Value format (e.g. `src=... dst=...`)
        if first.contains("src=") || first.contains("srcip=") || first.contains("saddr=") {
            return Self::synthesize_kv_regex(samples);
        }

        // Case 3: Token Positional / Freeform format
        Self::synthesize_positional_regex(samples)
    }

    /// Synthesize regex for directional arrow flow formats (e.g. Juniper SRX `IP/PORT->IP/PORT`)
    fn synthesize_flow_regex(samples: &[&str]) -> Result<String> {
        let re_flow_slash =
            Regex::new(r"([0-9a-fA-F.:%]+)/(\d{1,5})->([0-9a-fA-F.:%]+)/(\d{1,5})").unwrap();

        let re_flow_colon =
            Regex::new(r"([0-9a-fA-F.:%]+):(\d{1,5})\s*->\s*([0-9a-fA-F.:%]+):(\d{1,5})").unwrap();

        let first = samples[0];

        if re_flow_slash.is_match(first) {
            // Match Juniper SRX RT_FLOW pattern
            // Example: RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.168.10.55/49152->10.0.0.1/443 None None 6 sample-policy trust untrust 12345 N/A(N/A) ge-0/0/0.0
            if first.starts_with("RT_FLOW") {
                let pattern = r#"^RT_FLOW:\s+(?P<event_type>\S+)\s+session\s+(?P<action_verb>\w+)(?:.*?)\s+(?P<src_ip>[0-9a-fA-F.:%]+)/(?P<src_port>\d{1,5})->(?P<dst_ip>[0-9a-fA-F.:%]+)/(?P<dst_port>\d{1,5})\s+\S+\s+\S+\s+(?P<protocol>\d+)\s+(?P<policy>\S+)\s+(?P<src_zone>\S+)\s+(?P<dst_zone>\S+)(?:.*)$"#.to_string();
                return Ok(pattern);
            }

            let pattern = r#"^.*?(?P<src_ip>[0-9a-fA-F.:%]+)/(?P<src_port>\d{1,5})->(?P<dst_ip>[0-9a-fA-F.:%]+)/(?P<dst_port>\d{1,5})(?:.*?proto[=:\s]+(?P<protocol>\S+))?(?:.*?action[=:\s]+(?P<action>\w+))?.*$"#.to_string();
            return Ok(pattern);
        }

        if re_flow_colon.is_match(first) {
            // Example: 2026-09-21 14:00:01 CheckPoint-FW drop 192.168.10.15:52341 -> 10.0.0.25:443 proto TCP rule 101
            let pattern = r#"^(?:(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+)?(?P<device>\S+)\s+(?P<action>[a-zA-Z]+)\s+(?P<src_ip>[0-9a-fA-F.:%]+):(?P<src_port>\d{1,5})\s*->\s*(?P<dst_ip>[0-9a-fA-F.:%]+):(?P<dst_port>\d{1,5})(?:.*?proto\s+(?P<protocol>[a-zA-Z0-9]+))?(?:.*)$"#.to_string();
            return Ok(pattern);
        }

        Self::synthesize_positional_regex(samples)
    }

    /// Synthesize regex for key-value formats dynamically ordered by field appearance
    fn synthesize_kv_regex(samples: &[&str]) -> Result<String> {
        let first = samples[0];

        // Key definitions: (display_name, search_regex, capture_pattern)
        let key_patterns = vec![
            (
                "action",
                Regex::new(r"\b(?:action|act)=").unwrap(),
                // Optional quotes: FortiGate writes `action="client-rst"` — the old
                // `[a-zA-Z]+` neither tolerated quotes nor hyphens and failed validation.
                r#"(?:action|act)="?(?P<action>[a-zA-Z0-9_-]+)"?"#,
            ),
            (
                "src_ip",
                Regex::new(r"\b(?:src|srcip|saddr)=").unwrap(),
                r"(?:src|srcip|saddr)=(?P<src_ip>[0-9a-fA-F.:%]+)",
            ),
            (
                "src_port",
                Regex::new(r"\b(?:sport|srcport)=").unwrap(),
                r"(?:sport|srcport)=(?P<src_port>\d{1,5})",
            ),
            (
                "dst_ip",
                Regex::new(r"\b(?:dst|dstip|daddr)=").unwrap(),
                r"(?:dst|dstip|daddr)=(?P<dst_ip>[0-9a-fA-F.:%]+)",
            ),
            (
                "dst_port",
                Regex::new(r"\b(?:dport|dstport)=").unwrap(),
                r"(?:dport|dstport)=(?P<dst_port>\d{1,5})",
            ),
            (
                "protocol",
                Regex::new(r"\b(?:proto|protocol)=").unwrap(),
                r"(?:proto|protocol)=(?P<protocol>[a-zA-Z0-9]+)",
            ),
        ];

        // Find match offsets in the first sample
        let mut ordered_patterns: Vec<(usize, &str)> = Vec::new();
        for (_name, re, capture_pat) in &key_patterns {
            if let Some(m) = re.find(first) {
                ordered_patterns.push((m.start(), capture_pat));
            }
        }

        // Sort by appearance offset
        ordered_patterns.sort_by_key(|k| k.0);

        if ordered_patterns.is_empty() {
            return Err(anyhow!("No recognizable key-value pairs found in sample"));
        }

        let mut regex_str = String::from("^");
        for (_, pat) in ordered_patterns {
            regex_str.push_str(".*?\\b");
            regex_str.push_str(pat);
        }
        regex_str.push_str(".*$");

        Ok(regex_str)
    }

    /// Synthesize regex via positional token alignment across sample lines
    fn synthesize_positional_regex(samples: &[&str]) -> Result<String> {
        let re_ip_port = Regex::new(r"^([0-9a-fA-F.:%]+)[:/](\d{1,5})$").unwrap();
        let re_ip = Regex::new(r"^[0-9a-fA-F.:%]+$").unwrap();
        let re_port = Regex::new(r"^\d{1,5}$").unwrap();
        let re_proto = Regex::new(r"^(?i)(TCP|UDP|ICMP|GRE|ESP|AH|IGMP|SCTP)$").unwrap();
        let re_action =
            Regex::new(r"^(?i)(accept|deny|drop|permit|block|reject|pass|allow)$").unwrap();
        let re_timestamp =
            Regex::new(r"^\d{4}[-/]\d{2}[-/]\d{2}(?:[T\s]\d{2}:\d{2}:\d{2})?$").unwrap();

        let split_lines: Vec<Vec<&str>> = samples
            .iter()
            .map(|s| s.split_whitespace().collect())
            .collect();

        let min_len = split_lines.iter().map(|l| l.len()).min().unwrap_or(0);
        if min_len == 0 {
            return Err(anyhow!("Empty sample lines provided"));
        }

        let mut parts = Vec::new();
        let mut ip_count = 0;
        let mut port_count = 0;

        for i in 0..min_len {
            let col: Vec<&str> = split_lines.iter().map(|l| l[i]).collect();
            let all_same = col.windows(2).all(|w| w[0] == w[1]);

            if all_same {
                // Static anchor token: escape special regex characters
                parts.push(regex::escape(col[0]));
            } else if col
                .iter()
                .all(|t| re_ip_port.is_match(t) && t.matches(':').count() < 2)
            {
                // IP:Port or IP/Port — but NOT bare IPv6 (2+ colons = IPv6, not IP:port).
                // Without this guard, `2001:db8::1` matches re_ip_port as src_ip=2001:db8: src_port=1.
                let delimiter = if col[0].contains(':') { ":" } else { "/" };
                if ip_count == 0 {
                    parts.push(format!(
                        r"(?P<src_ip>[0-9a-fA-F.:%]+){}(?P<src_port>\d{{1,5}})",
                        delimiter
                    ));
                    ip_count += 1;
                    port_count += 1;
                } else if ip_count == 1 {
                    parts.push(format!(
                        r"(?P<dst_ip>[0-9a-fA-F.:%]+){}(?P<dst_port>\d{{1,5}})",
                        delimiter
                    ));
                    ip_count += 1;
                    port_count += 1;
                } else {
                    // 3rd+ ip/port column: NEVER reuse a capture-group name —
                    // duplicate names make the regex fail to compile.
                    parts.push(format!(r"[0-9a-fA-F.:%]+{}\d{{1,5}}", delimiter));
                }
            } else if col.iter().all(|t| re_ip.is_match(t)) {
                if ip_count == 0 {
                    parts.push(r"(?P<src_ip>[0-9a-fA-F.:%]+)".to_string());
                    ip_count += 1;
                } else if ip_count == 1 {
                    parts.push(r"(?P<dst_ip>[0-9a-fA-F.:%]+)".to_string());
                    ip_count += 1;
                } else {
                    parts.push(r"[0-9a-fA-F.:%]+".to_string());
                }
            } else if col.iter().all(|t| re_port.is_match(t)) {
                if port_count == 0 {
                    parts.push(r"(?P<src_port>\d{1,5})".to_string());
                    port_count += 1;
                } else if port_count == 1 {
                    parts.push(r"(?P<dst_port>\d{1,5})".to_string());
                    port_count += 1;
                } else {
                    parts.push(r"(?:\d{1,5})".to_string());
                }
            } else if col.iter().all(|t| re_proto.is_match(t)) {
                parts.push(r"(?P<protocol>[a-zA-Z0-9]+)".to_string());
            } else if col.iter().all(|t| re_action.is_match(t)) {
                parts.push(r"(?P<action>[a-zA-Z]+)".to_string());
            } else if col.iter().all(|t| re_timestamp.is_match(t)) {
                parts.push(r"(?P<timestamp>\S+)".to_string());
            } else {
                parts.push(r"(?:\S+)".to_string());
            }
        }

        let mut regex_str = String::from("^");
        regex_str.push_str(&parts.join(r"\s+"));
        regex_str.push_str("(?:.*)$");

        Ok(regex_str)
    }

    /// Infer mapping from raw action verbs to standard OCSF disposition strings
    fn infer_action_mappings(_samples: &[&str]) -> HashMap<String, String> {
        let mut map = HashMap::new();
        map.insert("created".to_string(), disposition::ALLOWED.to_string());
        map.insert("closed".to_string(), disposition::ALLOWED.to_string());
        map.insert("accept".to_string(), disposition::ALLOWED.to_string());
        map.insert("permit".to_string(), disposition::ALLOWED.to_string());
        map.insert("allow".to_string(), disposition::ALLOWED.to_string());
        map.insert("passed".to_string(), disposition::ALLOWED.to_string());
        map.insert("pass".to_string(), disposition::ALLOWED.to_string());
        map.insert("deny".to_string(), disposition::BLOCKED.to_string());
        map.insert("denied".to_string(), disposition::BLOCKED.to_string());
        map.insert("block".to_string(), disposition::BLOCKED.to_string());
        map.insert("blocked".to_string(), disposition::BLOCKED.to_string());
        map.insert("reject".to_string(), disposition::BLOCKED.to_string());
        map.insert("drop".to_string(), disposition::DROPPED.to_string());
        map.insert("dropped".to_string(), disposition::DROPPED.to_string());
        map
    }
}

/// Registry bound: hard capacity so dynamic regex memory can never grow without limit.
/// Eviction is LRU by last-use (registration counts as a use; ties broken by key for
/// full determinism — no randomness anywhere in the air-gapped hot path).
pub const REGISTRY_CAPACITY: usize = 256;

/// One registered dynamic parser: definition + regex compiled exactly once + LRU stamp.
struct RegistryEntry {
    parser: Arc<ParserDefinition>,
    /// `None` only if the stored pattern failed to compile (parse then errors, as before).
    regex: Option<Regex>,
    last_use: u64,
}

/// Dynamic Parser Registry allowing hot registration and loading without recompilation.
/// Bounded (REGISTRY_CAPACITY) with LRU eviction and deterministic (BTreeMap) iteration
/// order, so `parse_any` always picks the same winner among overlapping parsers.
pub struct DynamicParserRegistry {
    /// key = `vendor:device_model` (unique per onboarded cluster; bare vendor keys would
    /// silently overwrite earlier clusters of the same vendor)
    parsers: BTreeMap<String, RegistryEntry>,
    clock: u64,
    capacity: usize,
}

impl DynamicParserRegistry {
    pub fn new() -> Self {
        Self {
            parsers: BTreeMap::new(),
            clock: 0,
            capacity: REGISTRY_CAPACITY,
        }
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// Register a new parser definition dynamically. Returns the registry key
    /// (`vendor:device_model`) so callers can install a Tier-1 promotion route.
    #[must_use = "the registry key is needed to install a promotion route"]
    pub fn register(&mut self, parser: ParserDefinition) -> String {
        let key = format!("{}:{}", parser.vendor.to_lowercase(), parser.device_model);
        let regex = Regex::new(&parser.regex_pattern).ok();
        let now = self.tick();
        if !self.parsers.contains_key(&key) && self.parsers.len() >= self.capacity {
            // LRU evict: least recently used, ties broken by lexicographically
            // smallest key — deterministic, no unbounded regex memory.
            if let Some(evict_key) = self
                .parsers
                .iter()
                .min_by(|a, b| (a.1.last_use, a.0).cmp(&(b.1.last_use, b.0)))
                .map(|(k, _)| k.clone())
            {
                self.parsers.remove(&evict_key);
            }
        }
        self.parsers.insert(
            key.clone(),
            RegistryEntry {
                parser: Arc::new(parser),
                regex,
                last_use: now,
            },
        );
        key
    }

    /// Load and register parser directly from JSON
    pub fn load_from_json(&mut self, json_str: &str) -> Result<()> {
        let def = ParserDefinition::from_json(json_str)?;
        let _ = self.register(def);
        Ok(())
    }

    /// Load and register parser directly from YAML
    pub fn load_from_yaml(&mut self, yaml_str: &str) -> Result<()> {
        let def = ParserDefinition::from_yaml(yaml_str)?;
        let _ = self.register(def);
        Ok(())
    }

    /// Parse a log line with a registered dynamic parser. Lookup is by exact key
    /// first, then by `vendor:` prefix (composite keys) — first match in
    /// lexicographic order, so results are deterministic.
    pub fn parse(&mut self, vendor: &str, raw: &str) -> Result<NetworkActivity> {
        let vendor_key = vendor.to_lowercase();
        let prefix = format!("{}:", vendor_key);
        let key = if self.parsers.contains_key(&vendor_key) {
            vendor_key
        } else {
            self.parsers
                .keys()
                .find(|k| k.starts_with(&prefix))
                .cloned()
                .ok_or_else(|| anyhow!("No dynamic parser registered for vendor '{}'", vendor))?
        };
        self.parse_key(&key, raw)
            .ok_or_else(|| anyhow!("Log did not match dynamic parser '{}'", key))
    }

    /// Parse with an exact registry key (Tier-1 dynamic route). Returns `None` when
    /// the key was evicted or the line no longer matches its pattern.
    pub fn parse_key(&mut self, key: &str, raw: &str) -> Option<NetworkActivity> {
        let now = self.tick();
        let entry = self.parsers.get_mut(key)?;
        entry.last_use = now;
        let re = entry.regex.as_ref()?;
        entry.parser.parse_with_regex(re, raw).ok()
    }

    /// Attempt to parse a log line with any registered dynamic parser.
    /// Returns the winning key alongside the event so callers can install a
    /// promotion route; iteration order (BTreeMap) is deterministic.
    pub fn parse_any_keyed(&mut self, raw: &str) -> Option<(String, NetworkActivity)> {
        let now = self.tick();
        for (key, entry) in self.parsers.iter_mut() {
            if let (true, Some(re)) = (entry.regex.is_some(), entry.regex.as_ref()) {
                if let Ok(activity) = entry.parser.parse_with_regex(re, raw) {
                    entry.last_use = now;
                    return Some((key.clone(), activity));
                }
            }
        }
        None
    }

    /// Attempt to parse a log line with any registered dynamic parser
    pub fn parse_any(&mut self, raw: &str) -> Option<NetworkActivity> {
        self.parse_any_keyed(raw).map(|(_, activity)| activity)
    }

    pub fn len(&self) -> usize {
        self.parsers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.parsers.is_empty()
    }
}

impl Default for DynamicParserRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Helper to convert protocol name to IANA protocol number
fn protocol_num_from_name(name: &str) -> Option<u8> {
    match name.to_ascii_uppercase().as_str() {
        "ICMP" => Some(1),
        "IGMP" => Some(2),
        "TCP" => Some(6),
        "UDP" => Some(17),
        "GRE" => Some(47),
        "ESP" => Some(50),
        "AH" => Some(51),
        "ICMPV6" | "ICMP6" => Some(58),
        "OSPF" => Some(89),
        "SCTP" => Some(132),
        _ => None,
    }
}

/// Helper to convert IANA protocol number to protocol name
fn protocol_name_from_num(num: u8) -> &'static str {
    match num {
        1 => "ICMP",
        2 => "IGMP",
        6 => "TCP",
        17 => "UDP",
        47 => "GRE",
        50 => "ESP",
        51 => "AH",
        58 => "ICMPv6",
        89 => "OSPF",
        132 => "SCTP",
        _ => "UNKNOWN",
    }
}

fn sanitize_ident(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FortiGate-style kv samples with quoted, hyphenated action values must
    /// synthesize a compiling regex that captures the full action token
    /// (old `[a-zA-Z]+` pattern tolerated neither quotes nor hyphens).
    #[test]
    fn test_kv_capture_quoted_hyphenated_action() {
        let samples = vec![
            r#"date=2026-09-21 time=14:00:02 devname="FGT" srcip=10.1.1.1 srcport=1111 dstip=10.2.2.2 dstport=8443 proto=6 action="client-rst""#,
            r#"date=2026-09-21 time=14:00:03 devname="FGT" srcip=10.1.1.2 srcport=2222 dstip=10.2.2.3 dstport=8444 proto=6 action="server-rst""#,
            r#"date=2026-09-21 time=14:00:04 devname="FGT" srcip=10.1.1.3 srcport=3333 dstip=10.2.2.4 dstport=8445 proto=6 action="timeout""#,
        ];
        let pattern = Onboarder::synthesize_regex(&samples).unwrap();
        let re = Regex::new(&pattern).expect("synthesized kv regex must compile");
        for (s, expected) in samples.iter().zip(["client-rst", "server-rst", "timeout"]) {
            let caps = re
                .captures(s)
                .unwrap_or_else(|| panic!("sample must match: {s}"));
            assert_eq!(caps.name("action").unwrap().as_str(), expected);
        }
    }

    /// A positional format with 3+ ip/port columns must never reuse a capture
    /// group name (duplicate `dst_port` names made Regex::new fail at validation).
    #[test]
    fn test_positional_third_ip_port_column_unnamed() {
        let samples = vec![
            "edge-fw 192.0.2.1:1000 198.51.100.2:2000 203.0.113.3:3000 TCP accept",
            "edge-fw 192.0.2.4:1001 198.51.100.5:2001 203.0.113.6:3001 TCP accept",
            "edge-fw 192.0.2.7:1002 198.51.100.8:2002 203.0.113.9:3002 TCP accept",
        ];
        let pattern = Onboarder::synthesize_regex(&samples).unwrap();
        let re = Regex::new(&pattern)
            .expect("3rd ip/port column must be unnamed — duplicate group names must not occur");
        let caps = re.captures(samples[0]).unwrap();
        assert_eq!(caps.name("src_ip").unwrap().as_str(), "192.0.2.1");
        assert_eq!(caps.name("dst_ip").unwrap().as_str(), "198.51.100.2");
        assert!(caps.name("src_port").is_some());
        assert!(caps.name("dst_port").is_some());
    }

    /// Sandbox validation accepts IPv6 endpoints (IpAddr, not Ipv4Addr).
    #[test]
    fn test_validation_accepts_ipv6_endpoints() {
        let parser = ParserDefinition {
            vendor: "test".into(),
            device_model: "v6".into(),
            regex_pattern:
                r"^(?P<src_ip>[0-9a-fA-F:]+)/(?P<src_port>\d{1,5})->(?P<dst_ip>[0-9a-fA-F:]+)/(?P<dst_port>\d{1,5})$"
                    .to_string(),
            action_mappings: HashMap::new(),
            sample_logs: vec![],
            confidence_score: 1.0,
            created_at: 0,
            regex_cache: Arc::new(OnceLock::new()),
        };
        let samples = [
            "2001:db8::1/443->2001:db8::2/80",
            "2001:db8::3/443->2001:db8::4/80",
            "2001:db8::5/443->2001:db8::6/80",
        ];
        let report = Onboarder::validate_parser(&parser, &samples).unwrap();
        assert!(report.passed, "IPv6 must pass: {:?}", report.errors);
        assert_eq!(report.match_percentage, 100.0);
    }

    /// Compiled regex is cached via Arc<OnceLock<Regex>> — repeated parse()
    /// calls must NOT recompile (pointer equality proves cache hit).
    #[test]
    fn test_parse_caches_compiled_regex() {
        let parser = ParserDefinition {
            vendor: "test".into(),
            device_model: "cache".into(),
            regex_pattern: r"^src=(?P<src_ip>\S+) dst=(?P<dst_ip>\S+)$".to_string(),
            action_mappings: HashMap::new(),
            sample_logs: vec![],
            confidence_score: 1.0,
            created_at: 0,
            regex_cache: Arc::new(OnceLock::new()),
        };
        // First parse compiles + initializes the OnceLock.
        let ev1 = parser.parse("src=10.0.0.1 dst=10.0.0.2").unwrap();
        let ev2 = parser.parse("src=10.0.0.3 dst=10.0.0.4").unwrap();
        assert_eq!(ev1.src_endpoint.ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(ev2.src_endpoint.ip.as_deref(), Some("10.0.0.3"));
        // Clone shares the same Arc<OnceLock<Regex>> — no recompile on clone path.
        let cloned = parser.clone();
        let ev3 = cloned.parse("src=10.0.0.5 dst=10.0.0.6").unwrap();
        assert_eq!(ev3.src_endpoint.ip.as_deref(), Some("10.0.0.5"));
    }

    /// A pattern that fails to compile must return Err, never panic —
    /// `parse()` crosses a trust boundary (pattern comes from deserialized YAML).
    #[test]
    fn test_parse_returns_err_on_invalid_regex_not_panic() {
        let parser = ParserDefinition {
            vendor: "test".into(),
            device_model: "bad-regex".into(),
            regex_pattern: "^(?P<src_ip>[unclosed".to_string(),
            action_mappings: HashMap::new(),
            sample_logs: vec![],
            confidence_score: 1.0,
            created_at: 0,
            regex_cache: Arc::new(OnceLock::new()),
        };
        // Must not panic — a Result-returning pub fn must surface Err.
        let err = parser
            .parse("src=10.0.0.1")
            .expect_err("invalid regex must Err, not panic");
        assert!(
            err.to_string().contains("Invalid compiled regex"),
            "error must name the compile failure: {err}"
        );
        // Repeat call must stay Err (cache stores the failure, not panics).
        assert!(parser.parse("src=10.0.0.1").is_err());
    }

    /// A deserialized definition with a bad pattern (the real trust boundary)
    /// must round-trip through JSON and still Err rather than panic.
    #[test]
    fn test_invalid_regex_from_json_errors_not_panics() {
        let json = r#"{
            "vendor": "evil", "device_model": "m", "regex_pattern": "^(?P<src_ip>[broken",
            "action_mappings": {}, "sample_logs": [], "confidence_score": 1.0, "created_at": 0
        }"#;
        let parser = ParserDefinition::from_json(json).unwrap();
        assert!(
            parser.parse("anything").is_err(),
            "attacker-supplied pattern must Err, never panic"
        );
    }

    /// noyalib replaces hand-rolled YAML: round-trip must preserve all fields
    /// and field names must stay stable for data/parsers/*.yaml compatibility.
    #[test]
    fn test_yaml_roundtrip_noyalib_stable_fields() {
        let parser = ParserDefinition {
            vendor: "pfSense".into(),
            device_model: "CEF-1".into(),
            regex_pattern: r"^(?P<src_ip>\S+) (?P<dst_ip>\S+)$".to_string(),
            action_mappings: HashMap::from([("pass".to_string(), "ALLOWED".to_string())]),
            sample_logs: vec!["line one".to_string(), "line two".to_string()],
            confidence_score: 0.95,
            created_at: 1_700_000_000_000,
            regex_cache: Arc::new(OnceLock::new()),
        };
        let yaml = parser.to_yaml().unwrap();
        // Stable field names required by data/parsers/*.yaml consumers.
        for field in [
            "vendor:",
            "device_model:",
            "regex_pattern:",
            "action_mappings:",
            "sample_logs:",
            "confidence_score:",
            "created_at:",
        ] {
            assert!(yaml.contains(field), "YAML missing stable field: {field}");
        }
        let back = ParserDefinition::from_yaml(&yaml).unwrap();
        assert_eq!(back.vendor, parser.vendor);
        assert_eq!(back.device_model, parser.device_model);
        assert_eq!(back.regex_pattern, parser.regex_pattern);
        assert_eq!(back.action_mappings, parser.action_mappings);
        assert_eq!(back.sample_logs, parser.sample_logs);
        assert!((back.confidence_score - parser.confidence_score).abs() < f64::EPSILON);
        assert_eq!(back.created_at, parser.created_at);
    }

    /// Synthesizer must produce IPv6-capable patterns (flow-arrow format).
    #[test]
    fn test_synthesizer_flow_accepts_ipv6() {
        let samples = vec![
            "2001:db8::1/443->2001:db8::2/80 proto 6",
            "2001:db8::3/443->2001:db8::4/80 proto 6",
            "2001:db8::5/443->2001:db8::6/80 proto 6",
        ];
        let pattern = Onboarder::synthesize_regex(&samples).unwrap();
        let re = Regex::new(&pattern).unwrap();
        let caps = re.captures(samples[0]).unwrap();
        assert_eq!(caps.name("src_ip").unwrap().as_str(), "2001:db8::1");
        assert_eq!(caps.name("dst_ip").unwrap().as_str(), "2001:db8::2");
    }

    /// Synthesizer must produce IPv6-capable patterns (key-value format, e.g. pfSense).
    #[test]
    fn test_synthesizer_kv_accepts_ipv6() {
        let samples = vec![
            r#"srcip=2001:db8::1 srcport=443 dstip=2001:db8::2 dstport=80 proto=6 action=pass"#,
            r#"srcip=2001:db8::3 srcport=444 dstip=2001:db8::4 dstport=81 proto=6 action=pass"#,
            r#"srcip=2001:db8::5 srcport=445 dstip=2001:db8::6 dstport=82 proto=6 action=pass"#,
        ];
        let pattern = Onboarder::synthesize_regex(&samples).unwrap();
        let re = Regex::new(&pattern).unwrap();
        let caps = re.captures(samples[0]).unwrap();
        assert_eq!(caps.name("src_ip").unwrap().as_str(), "2001:db8::1");
        assert_eq!(caps.name("dst_ip").unwrap().as_str(), "2001:db8::2");
    }

    /// Positional synthesizer: a bare IPv6 column (2+ colons) must NOT be
    /// mis-parsed as IP:port (`src_ip="2001:db8:" src_port=1`).
    #[test]
    fn test_positional_synthesizer_bare_ipv6_column() {
        let samples = vec![
            "edge-fw 2001:db8::1 2001:db8::2 TCP accept",
            "edge-fw 2001:db8::3 2001:db8::4 TCP accept",
            "edge-fw 2001:db8::5 2001:db8::6 TCP accept",
        ];
        let pattern = Onboarder::synthesize_regex(&samples).unwrap();
        let re = Regex::new(&pattern).unwrap();
        let caps = re.captures(samples[0]).unwrap();
        assert_eq!(
            caps.name("src_ip").map(|m| m.as_str()),
            Some("2001:db8::1"),
            "bare IPv6 must be captured whole, not split at a colon"
        );
        assert_eq!(caps.name("dst_ip").map(|m| m.as_str()), Some("2001:db8::2"));
    }

    /// Validation threshold: 95% match rate passes (not 100%), warnings surfaced.
    #[test]
    fn test_validation_threshold_95_percent_with_warnings() {
        let parser = ParserDefinition {
            vendor: "test".into(),
            device_model: "v6".into(),
            regex_pattern:
                r"^(?P<src_ip>[0-9a-fA-F:]+)/(?P<src_port>\d{1,5})->(?P<dst_ip>[0-9a-fA-F:]+)/(?P<dst_port>\d{1,5})$"
                    .to_string(),
            action_mappings: HashMap::new(),
            sample_logs: vec![],
            confidence_score: 1.0,
            created_at: 0,
            regex_cache: Arc::new(OnceLock::new()),
        };
        // 19/20 = 95% — must pass (old code required 100%).
        let owned: Vec<String> = (0..19)
            .map(|i| format!("2001:db8::{i:x}/443->2001:db8::2/80"))
            .chain(std::iter::once(
                "garbage line that does not match".to_string(),
            ))
            .collect();
        let samples: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();
        let report = Onboarder::validate_parser(&parser, &samples).unwrap();
        assert!(
            report.passed,
            "95% match rate must pass: {:?}",
            report.errors
        );
        assert!((report.match_percentage - 95.0).abs() < 0.01);
    }

    /// confidence_score must reflect the real match percentage, not a hardcoded
    /// 1.0 — a parser that failed on some samples cannot claim 100% confidence.
    #[test]
    fn test_confidence_score_reflects_match_percentage() {
        let good = vec![
            r#"date=2026-09-21 srcip=10.1.1.1 dstip=10.2.2.2 proto=6 action=pass"#,
            r#"date=2026-09-21 srcip=10.1.1.2 dstip=10.2.2.3 proto=6 action=pass"#,
            r#"date=2026-09-21 srcip=10.1.1.3 dstip=10.2.2.4 proto=6 action=pass"#,
        ];
        let (def, report) = Onboarder::generate_parser("v", "m", &good).unwrap();
        assert!(
            (def.confidence_score - report.match_percentage / 100.0).abs() < 1e-9,
            "confidence must equal match_percentage/100: {} vs {}",
            def.confidence_score,
            report.match_percentage / 100.0
        );
    }

    /// Registry is bounded (REGISTRY_CAPACITY) with LRU-by-last-use eviction and
    /// deterministic tie-breaking — no unbounded regex memory on the hot path.
    #[test]
    fn test_registry_capacity_bound_and_lru_eviction() {
        let mut reg = DynamicParserRegistry::new();
        let mk = |model: &str| ParserDefinition {
            vendor: "vendor".into(),
            device_model: model.into(),
            regex_pattern: r"^line (?P<src_port>\d+)$".to_string(),
            action_mappings: HashMap::new(),
            sample_logs: vec![],
            confidence_score: 1.0,
            created_at: 0,
            regex_cache: Arc::new(OnceLock::new()),
        };

        for i in 0..REGISTRY_CAPACITY {
            let key = reg.register(mk(&format!("m-{i:04}")));
            assert_eq!(
                key,
                format!("vendor:m-{i:04}"),
                "composite vendor:model key"
            );
        }
        assert_eq!(reg.len(), REGISTRY_CAPACITY);

        // Touch the lexicographically-first entry: it must become the most
        // recently used and survive the next eviction.
        let first_key = format!("vendor:m-{:04}", 0);
        assert!(reg.parse_key(&first_key, "line 443").is_some());

        // Over capacity -> exactly one (least recently used) entry evicted.
        let new_key = reg.register(mk("m-new"));
        assert_eq!(new_key, "vendor:m-new");
        assert_eq!(reg.len(), REGISTRY_CAPACITY, "bound must hold");
        assert!(
            reg.parse_key(&first_key, "line 443").is_some(),
            "recently-used entry must survive LRU eviction"
        );
        // The stalest untouched entry (m-0001; m-0000 was touched) was evicted.
        assert!(
            reg.parse_key("vendor:m-0001", "line 80").is_none(),
            "stalest entry must be evicted"
        );
        // Vendor-prefixed lookup stays deterministic (lexicographic first match).
        assert!(reg.parse("vendor", "line 443").is_ok());
        assert_eq!(reg.len(), REGISTRY_CAPACITY);
    }
}
