use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use uuid::Uuid;

use ulpf_core::schema::ocsf::{
    activity_id, disposition, ConnectionInfo, Endpoint, Metadata, NetworkActivity, Product,
};

/// Schema version stamped on every synthesized parser definition.
///
/// Bumped whenever the `ParserDefinition` serialization shape changes so
/// loaders can distinguish current files from legacy ones. Deserialization
/// defaults a missing field to 0 (see the `#[serde(default)]` on
/// [`ParserDefinition::schema_version`]), so parsers published before this
/// field existed keep loading — they just report version 0.
pub const PARSER_SCHEMA_VERSION: u32 = 1;
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
/// compiled-regex cache.
///
/// # Why `Clone` and `PartialEq` are hand-written
///
/// `regex_cache` is `Arc<OnceLock<Result<Regex, regex::Error>>>`. `OnceLock`
/// implements neither `Clone` nor `PartialEq`, and `Arc<T>` inherits both
/// limits, so neither can be derived. `Clone` is implemented by hand and
/// deliberately hands out a **fresh, empty** cell rather than a clone of the
/// warm one — see [`ParserDefinition::clone`]. There is no `PartialEq` impl at
/// all: comparing two definitions field-by-field while ignoring the cache would
/// claim they are equal when one is holding a compiled regex and the other is
/// not, and comparing the caches would compare `regex::Error` values. Callers
/// that need equality should compare the serialized form, which is what
/// actually round-trips.
#[derive(Debug, Serialize, Deserialize)]
pub struct ParserDefinition {
    pub vendor: String,
    pub device_model: String,
    /// The synthesis pattern. **Treat as immutable after construction.**
    /// `regex_cache` is a write-once `OnceLock`: if this field is mutated after
    /// the first `parse()`, the cache keeps serving the ORIGINAL compiled
    /// pattern (or keeps failing), silently disagreeing with the field — and
    /// `to_json`/`to_yaml` would then serialize a pattern that is not applied.
    /// Rebuild the definition instead of mutating it in place.
    pub regex_pattern: String,
    pub action_mappings: HashMap<String, String>,
    pub sample_logs: Vec<String>,
    pub confidence_score: f64,
    pub created_at: i64,
    /// Schema version of this definition. `#[serde(default)]` (→ 0 when
    /// absent) is load-bearing, not laziness: `from_yaml` rejects missing
    /// fields, so without the default every parser file published before this
    /// field existed would stop loading. New files are stamped
    /// [`PARSER_SCHEMA_VERSION`]; legacy files report 0.
    #[serde(default)]
    pub schema_version: u32,
    #[serde(skip)]
    pub regex_cache: Arc<OnceLock<Result<Regex, regex::Error>>>,
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
            schema_version: self.schema_version,
            // A FRESH cell, deliberately: `regex_pattern` is public, so a clone
            // may re-pattern itself. Sharing the cell would leave the clone
            // silently parsing with the ORIGINAL pattern, disagreeing with the
            // field that `to_json`/`to_yaml` serialize. The cache is a pure
            // per-object optimization — sharing it across objects buys nothing
            // (the registry compiles its own `Regex` at register time) and costs
            // correctness.
            regex_cache: Arc::new(OnceLock::new()),
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
    /// Uses the cached compiled regex (Arc<OnceLock<Result<Regex, Error>>>) — no
    /// per-event recompile. Returns Err if the pattern fails to compile (never
    /// panics): the compile ERROR is cached too, so a bad definition reports the
    /// same diagnosable message on every event instead of retrying a hopeless
    /// compile or panicking a `Result`-returning fn.
    pub fn parse(&self, raw: &str) -> Result<NetworkActivity> {
        let compiled_re = self
            .regex_cache
            .get_or_init(|| Regex::new(&self.regex_pattern))
            .as_ref()
            .map_err(|e| {
                anyhow!(
                    "Invalid compiled regex in parser definition '{}': {e}",
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

        // 1. Extract Endpoints. A present endpoint capture must be a REAL
        // address (`parse_ip`, i.e. `IpAddr::from_str` modulo the zone id) —
        // the same check `validate_parser` applies. A pattern whose `src_ip`
        // group captures `14:00` or any other non-address must fail the event,
        // not file it under a garbage IP: bare IPv6 (`2001:db8::1`) passes
        // intact, anything unparseable is an Err like a validation miss.
        // `Endpoint` has no hostname field, so a non-address was never a valid
        // value here — accepting one was silently corrupting the store.
        //
        // Cost: two `IpAddr::from_str` calls, measured once at ~250 ns/event in
        // release on a ~1.2 us call — i.e. the novel-vendor dynamic route, not
        // the line-rate hot path (that is Tier-1's `SignatureLruCache`, and it
        // never reaches here). Treat the figure as a one-off measurement on one
        // machine, not a committed benchmark. Only unknown shapes get this far,
        // and it buys a guarantee that no event is ever filed under a fabricated
        // address. Revisit only alongside a cheaper address check, never by
        // dropping the check.
        let src_ip_raw = caps.name("src_ip").map(|m| m.as_str());
        if let Some(s) = src_ip_raw {
            if parse_ip(s).is_none() {
                anyhow::bail!("Invalid src_ip endpoint capture: '{s}'");
            }
        }
        let dst_ip_raw = caps.name("dst_ip").map(|m| m.as_str());
        if let Some(s) = dst_ip_raw {
            if parse_ip(s).is_none() {
                anyhow::bail!("Invalid dst_ip endpoint capture: '{s}'");
            }
        }
        let src_ip = src_ip_raw.map(|s| s.to_string());
        let dst_ip = dst_ip_raw.map(|s| s.to_string());

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
    regex: OnceLock<Result<Regex, regex::Error>>,
}

impl __VENDOR____MODEL__Extractor {
    pub fn new() -> Self {
        Self { regex: OnceLock::new() }
    }

    pub fn parse(&self, raw: &str) -> anyhow::Result<NetworkActivity> {
        // Cache the compile ERROR too, so a bad pattern reports a diagnosable
        // failure on every event instead of panicking this Result-returning fn.
        let re = self
            .regex
            .get_or_init(|| Regex::new(r"__PATTERN__"))
            .as_ref()
            .map_err(|e| anyhow::anyhow!("Invalid regex for __VENDOR__: {e}"))?;

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
    /// Analyze sample lines of an unknown perimeter device log,
    /// synthesize a non-greedy compiled regex with named capture groups,
    /// perform sandbox validation, and produce an exportable
    /// `ParserDefinition`.
    ///
    /// At least 3 samples are required. The 95% pass-rate threshold is only a
    /// genuine 95% from 20 samples up: the rule is `failed <= total / 20`, so
    /// below 20 it allows zero failures and is effectively a 100% requirement.
    /// Supplying fewer samples is not wrong, it just buys no relaxation —
    /// which is why `ulpf onboard` reads up to 25 rather than a handful.
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
            schema_version: PARSER_SCHEMA_VERSION,
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

    /// Automated Sandbox Validation: verifies samples match and extract valid
    /// IPs and ports. Strict (100%) below 20 samples; ≥95% at/above 20, where
    /// the residual failures are surfaced as warnings in `errors`.
    pub fn validate_parser(
        parser: &ParserDefinition,
        samples: &[&str],
    ) -> Result<ValidationReport> {
        let compiled_re = Regex::new(&parser.regex_pattern)
            .with_context(|| format!("Failed to compile regex: {}", parser.regex_pattern))?;

        let mut matched = 0;
        let mut evaluated = 0;
        let mut errors = Vec::new();

        for sample in samples {
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
                        evaluated, line
                    ));
                    continue;
                }
            };

            // Validate src_ip
            let src_ip_opt = caps.name("src_ip").map(|m| m.as_str());
            match src_ip_opt {
                Some(ip_str) => {
                    if parse_ip(ip_str).is_none() {
                        errors.push(format!(
                            "Sample #{}: invalid IP for src_ip: '{}'",
                            evaluated, ip_str
                        ));
                        continue;
                    }
                }
                None => {
                    errors.push(format!(
                        "Sample #{}: missing required capture group 'src_ip'",
                        evaluated
                    ));
                    continue;
                }
            }

            // Validate dst_ip
            let dst_ip_opt = caps.name("dst_ip").map(|m| m.as_str());
            match dst_ip_opt {
                Some(ip_str) => {
                    if parse_ip(ip_str).is_none() {
                        errors.push(format!(
                            "Sample #{}: invalid IP for dst_ip: '{}'",
                            evaluated, ip_str
                        ));
                        continue;
                    }
                }
                None => {
                    errors.push(format!(
                        "Sample #{}: missing required capture group 'dst_ip'",
                        evaluated
                    ));
                    continue;
                }
            }

            // Validate ports if present
            if let Some(sp) = caps.name("src_port") {
                if sp.as_str().parse::<u16>().is_err() {
                    errors.push(format!(
                        "Sample #{}: invalid port for src_port: '{}'",
                        evaluated,
                        sp.as_str()
                    ));
                    continue;
                }
            }

            if let Some(dp) = caps.name("dst_port") {
                if dp.as_str().parse::<u16>().is_err() {
                    errors.push(format!(
                        "Sample #{}: invalid port for dst_port: '{}'",
                        evaluated,
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

        // 95% gate as an integer rule: nonzero total, at most total/20
        // failures. No float, no `max(1)`, no special-case floor — below 20
        // samples `total / 20 == 0`, so the gate is strict (100%): at N=3 a
        // single failure is 33%, which is not a 95% rule. At N=20 exactly one
        // failure is allowed (19/20). Zero evaluated samples always fails: an
        // unvalidated parser must never be admitted, and `0 == 0` would
        // otherwise report a vacuous pass.
        let failed = total - matched;
        let passed = total > 0 && failed <= total / 20;

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

        // Case 0: ArcSight CEF — checked FIRST, before the flow-arrow branch.
        // A CEF extension block can legally contain `->` or the word
        // `session`, either of which would route the sample into
        // `synthesize_flow_regex` and build a pattern around the wrong
        // anchor (the KV branch would also misfire on `src=` while missing
        // the CEF-short `spt=`/`dpt=` port keys entirely).
        if first.contains("CEF:") {
            return Self::synthesize_cef_regex(samples);
        }

        // Case 0b: JSON / Suricata EVE — a trimmed leading `{` is unambiguous
        // (no other branch handles it; today these fall through to the
        // positional tokenizer, which shreds them on whitespace). Tried
        // before the flow-arrow branch: an EVE `signature` string can legally
        // contain `->`. A sample that merely starts with `{` but is not valid
        // JSON falls through to the branches below.
        if first.trim_start().starts_with('{') {
            if let Ok(pattern) = Self::synthesize_json_regex(samples) {
                return Ok(pattern);
            }
        }

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

    /// Synthesize regex for ArcSight CEF (`CEF:v|vendor|product|version|sig|name|sev|ext`).
    ///
    /// Over-match guards (a CEF pattern must never fire on other vendors'
    /// traffic — see the cross-vendor sweep test):
    /// - the `CEF:\d+|` header anchor is mandatory, not optional;
    /// - every extension key is prefixed with `\b` (`src=` must not match
    ///   inside `srcintf=` or `srcip=`);
    /// - `act=` is a mandatory clause whenever sample 1 carries it, and
    ///   `src=`/`dst=` are always mandatory — without endpoints the sandbox
    ///   validator rejects the pattern anyway, so fail loudly here instead.
    ///
    /// The action group reuses the `action` capture name so
    /// `parse_with_regex` maps it with no runtime change.
    fn synthesize_cef_regex(samples: &[&str]) -> Result<String> {
        let first = samples[0];

        // CEF-short extension keys in first-sample offset order. The KV
        // branch only knows `sport=`/`srcport=`/`dport=` and misses `spt=`
        // and `dpt=` entirely — which is why CEF gets its own synthesizer.
        let key_patterns = vec![
            (
                "action",
                static_re(r"\bact=")?,
                // CEF verbs carry hyphens (`client-rst`); tolerate the
                // quoted FortiGate form the same way the KV branch does.
                r#"(?:act)="?(?P<action>[a-zA-Z0-9_-]+)"?"#,
            ),
            (
                "src_ip",
                static_re(r"\bsrc=")?,
                r"(?:src)=(?P<src_ip>[0-9a-fA-F.:%]+)",
            ),
            (
                "src_port",
                static_re(r"\bspt=")?,
                r"(?:spt)=(?P<src_port>\d{1,5})",
            ),
            (
                "dst_ip",
                static_re(r"\bdst=")?,
                r"(?:dst)=(?P<dst_ip>[0-9a-fA-F.:%]+)",
            ),
            (
                "dst_port",
                static_re(r"\bdpt=")?,
                r"(?:dpt)=(?P<dst_port>\d{1,5})",
            ),
            (
                "protocol",
                static_re(r"\bproto=")?,
                r"(?:proto)=(?P<protocol>[a-zA-Z0-9]+)",
            ),
        ];

        let mut ordered_patterns: Vec<(usize, &str, &str)> = Vec::new();
        for (name, re, capture_pat) in &key_patterns {
            if let Some(m) = re.find(first) {
                ordered_patterns.push((m.start(), name, capture_pat));
            }
        }
        ordered_patterns.sort_by_key(|k| k.0);

        // Endpoints are non-negotiable: a pattern without `src_ip`/`dst_ip`
        // captures can never pass the sandbox validator, so say so now with
        // the sample attached instead of failing validation opaquely later.
        for required in ["src_ip", "dst_ip"] {
            if !ordered_patterns.iter().any(|(_, n, _)| *n == required) {
                return Err(anyhow!(
                    "No CEF endpoint key for '{required}' in sample: '{first}'"
                ));
            }
        }
        if ordered_patterns.is_empty() {
            return Err(anyhow!(
                "No recognizable CEF extension keys found in sample"
            ));
        }

        // Seven `|`-separated header fields; `[^|]*` per field so an empty
        // field (or a `dvchost` tail) never breaks the anchor. Header names
        // are `cef_`-prefixed: unknown to `parse_with_regex`, so they land
        // in `unmapped` as provenance instead of colliding with endpoints.
        let mut regex_str = String::from(
            r"^.*?CEF:(?P<cef_version>\d+)\|(?P<cef_vendor>[^|]*)\|(?P<cef_product>[^|]*)\|(?P<cef_device_version>[^|]*)\|(?P<cef_sig_id>[^|]*)\|(?P<cef_name>[^|]*)\|(?P<cef_severity>[^|]*)\|",
        );
        for (_, _, pat) in ordered_patterns {
            regex_str.push_str(r".*?\b");
            regex_str.push_str(pat);
        }
        regex_str.push_str(".*$");

        Ok(regex_str)
    }

    /// Synthesize regex for JSON log lines (Suricata EVE-JSON shape).
    ///
    /// Option A: parse the samples with `serde_json` (already a direct
    /// dependency — nothing new), flatten each document to key paths, and
    /// emit ONE regex anchored at `^\s*\{` whose clauses are
    /// `regex::escape`'d literal keys joined by `.*?`. There is deliberately
    /// NO hand-regexed JSON grammar here: quoting, nesting, and key order
    /// are handled by matching literal keys, not by parsing JSON with regex.
    ///
    /// Clause order follows the keys' offsets in the first sample's raw text
    /// (`serde_json::Map` is alphabetically ordered without `preserve_order`,
    /// so document order is read off the raw string, KV-branch style). A key
    /// path present in EVERY sample becomes a mandatory clause; a path seen
    /// only in some (e.g. `alert.action`, absent from EVE `flow`/`dns`
    /// records) becomes `(?:...)?` — otherwise a mixed-type training set
    /// could never validate. The value class follows the observed JSON type:
    /// strings match quoted, numbers bare, mixed either.
    fn synthesize_json_regex(samples: &[&str]) -> Result<String> {
        let first = samples[0];
        let first_val: serde_json::Value = serde_json::from_str(first)
            .with_context(|| "First sample is not valid JSON".to_string())?;

        // All samples must be JSON documents; a non-JSON sample means this
        // branch was mis-dispatched (caller falls through on our Err).
        let mut parsed: Vec<serde_json::Value> = Vec::with_capacity(samples.len());
        for s in samples {
            parsed.push(
                serde_json::from_str(s)
                    .with_context(|| "JSON synthesizer requires all samples to be JSON")?,
            );
        }

        // Flatten the first document to scalar key paths (objects only;
        // arrays carry no endpoint material and are skipped).
        let mut leaves: Vec<Vec<String>> = Vec::new();
        Self::flatten_json_leaves(&first_val, &mut Vec::new(), &mut leaves);

        // Keep only leaves that alias to a canonical endpoint/action name,
        // in first-sample raw-text offset order.
        let mut ordered: Vec<(usize, Vec<String>, &'static str)> = Vec::new();
        for path in &leaves {
            let leaf = &path[path.len() - 1];
            if let Some(canonical) = json_alias(leaf) {
                // Offset of the leaf key's quoted literal in the raw sample.
                let needle = format!("\"{leaf}\"");
                if let Some(off) = first.find(&needle) {
                    ordered.push((off, path.clone(), canonical));
                }
            }
        }
        ordered.sort_by_key(|k| k.0);
        if ordered.is_empty() {
            return Err(anyhow!("No endpoint/action keys found in JSON sample"));
        }

        // Unique capture names under the same budget rule as the positional
        // synthesizer: the first claimant takes the canonical name, a repeat
        // (e.g. top-level `action` plus nested `alert.action`) takes the
        // `parent_canonical` suffix, a third degrades to non-capturing.
        let mut taken: HashSet<String> = HashSet::new();
        let mut resolve_name = |canonical: &'static str, parent: Option<&str>| -> Option<String> {
            if taken.insert(canonical.to_string()) {
                return Some(canonical.to_string());
            }
            if let Some(p) = parent {
                let clean: String = p.chars().filter(|c| c.is_alphanumeric()).collect();
                let suffixed = format!("{clean}_{canonical}");
                if taken.insert(suffixed.clone()) {
                    return Some(suffixed);
                }
            }
            None
        };

        let mut regex_str = String::from(r"^\s*\{");
        for (_, path, canonical) in ordered {
            let leaf = &path[path.len() - 1];
            let parent = if path.len() > 1 {
                Some(path[path.len() - 2].as_str())
            } else {
                None
            };

            // Presence + value class across ALL samples: unanimous paths are
            // mandatory clauses, partial paths `(?:...)?` — a mixed-type
            // training set (alert/flow/dns) could never validate otherwise.
            let mut present = 0;
            let mut saw_str = false;
            let mut saw_num = false;
            for v in &parsed {
                if let Some((is_str, is_num)) = json_path_scalar(v, &path) {
                    present += 1;
                    saw_str |= is_str;
                    saw_num |= is_num;
                }
            }
            if present == 0 {
                continue;
            }
            let mandatory = present == parsed.len();

            let value_pat = match canonical {
                "src_ip" | "dst_ip" => r#"[^"]+"#,
                "src_port" | "dst_port" => r"\d{1,5}",
                "protocol" => r"[A-Za-z0-9]+",
                _ => r"[A-Za-z0-9_-]+", // action
            };
            let key_lit = regex::escape(leaf);
            let inner = match resolve_name(canonical, parent) {
                Some(name) => format!("(?P<{name}>{value_pat})"),
                None => format!("(?:{value_pat})"),
            };
            let clause = if saw_str && !saw_num {
                format!(r#""{key_lit}"\s*:\s*"{inner}""#)
            } else if saw_num && !saw_str {
                // Numeric endpoints are bare in EVE (`"src_port": 56529`).
                format!(r#""{key_lit}"\s*:\s*{inner}"#)
            } else {
                format!(r#""{key_lit}"\s*:\s*"?{inner}"?"#)
            };
            // A nested path (`alert.action`) scopes the leaf inside its
            // parent object; `[^}]*?` (not `.*?`) keeps the join from
            // spilling past the parent's closing brace.
            let scoped = if let Some(p) = parent {
                let parent_lit = regex::escape(p);
                format!(r#""{parent_lit}"\s*:\s*\{{[^}}]*?{clause}"#)
            } else {
                clause
            };
            if mandatory {
                regex_str.push_str(".*?");
                regex_str.push_str(&scoped);
            } else {
                regex_str.push_str("(?:.*?");
                regex_str.push_str(&scoped);
                regex_str.push_str(")?");
            }
        }
        regex_str.push_str(".*$");

        // The pattern must actually compile — `resolve_name` keeps names
        // unique, but prove it here rather than at validation time.
        static_re(&regex_str)?;
        Ok(regex_str)
    }

    /// Recursively collect scalar (string/number) key paths of a JSON
    /// document. Objects are descended; arrays, bools, and nulls are skipped
    /// — none of them alias to an endpoint or action capture.
    fn flatten_json_leaves(
        value: &serde_json::Value,
        prefix: &mut Vec<String>,
        out: &mut Vec<Vec<String>>,
    ) {
        if let Some(obj) = value.as_object() {
            for (k, v) in obj {
                prefix.push(k.clone());
                if v.is_string() || v.is_number() {
                    out.push(prefix.clone());
                } else if v.is_object() {
                    Self::flatten_json_leaves(v, prefix, out);
                }
                prefix.pop();
            }
        }
    }

    /// Synthesize regex for directional arrow flow formats (e.g. Juniper SRX `IP/PORT->IP/PORT`)
    fn synthesize_flow_regex(samples: &[&str]) -> Result<String> {
        let re_flow_slash = static_re(r"([0-9a-fA-F.:%]+)/(\d{1,5})->([0-9a-fA-F.:%]+)/(\d{1,5})")?;

        let re_flow_colon =
            static_re(r"([0-9a-fA-F.:%]+):(\d{1,5})\s*->\s*([0-9a-fA-F.:%]+):(\d{1,5})")?;

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
                static_re(r"\b(?:action|act)=")?,
                // Optional quotes: FortiGate writes `action="client-rst"` — the old
                // `[a-zA-Z]+` neither tolerated quotes nor hyphens and failed validation.
                r#"(?:action|act)="?(?P<action>[a-zA-Z0-9_-]+)"?"#,
            ),
            (
                "src_ip",
                static_re(r"\b(?:src|srcip|saddr)=")?,
                r"(?:src|srcip|saddr)=(?P<src_ip>[0-9a-fA-F.:%]+)",
            ),
            (
                "src_port",
                static_re(r"\b(?:sport|srcport)=")?,
                r"(?:sport|srcport)=(?P<src_port>\d{1,5})",
            ),
            (
                "dst_ip",
                static_re(r"\b(?:dst|dstip|daddr)=")?,
                r"(?:dst|dstip|daddr)=(?P<dst_ip>[0-9a-fA-F.:%]+)",
            ),
            (
                "dst_port",
                static_re(r"\b(?:dport|dstport)=")?,
                r"(?:dport|dstport)=(?P<dst_port>\d{1,5})",
            ),
            (
                "protocol",
                static_re(r"\b(?:proto|protocol)=")?,
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
        let re_ip_port = static_re(r"^([0-9a-fA-F.:%]+)[:/](\d{1,5})$")?;
        let re_port = static_re(r"^\d{1,5}$")?;
        let re_proto = static_re(r"^(?i)(TCP|UDP|ICMP|GRE|ESP|AH|IGMP|SCTP)$")?;
        let re_action = static_re(r"^(?i)(accept|deny|drop|permit|block|reject|pass|allow)$")?;
        let re_timestamp = static_re(r"^\d{4}[-/]\d{2}[-/]\d{2}(?:[T\s]\d{2}:\d{2}:\d{2})?$")?;

        // Classification uses REAL address validation, never a character class.
        // A permissive `[0-9a-fA-F.:%]+` also matches a wall-clock `14:00:01`,
        // so a time-of-day column was captured as `src_ip=14:00` +
        // `src_port=01` and then rejected by `validate_parser` — three samples,
        // zero parsers. `is_ip`/`is_ip_port` reject it and it falls through to
        // `(?:\S+)`, so the timestamp branch below only ever sees a
        // DATE-prefixed column (`re_timestamp` requires `\d{4}-\d{2}-\d{2}`).
        // `parse_ip` is also the only thing that can separate a bare IPv6
        // address from the ambiguous `addr:port` form: `2001:db8::1` and
        // `::443` are legal readings on BOTH sides, so neither a character class
        // nor a colon count can decide it. Only "does this whole token parse as
        // an address" can — hence the complete-valid-address check running
        // before the split is even attempted.
        let is_ip_port = |token: &str| {
            parse_ip(token).is_none()
                && re_ip_port
                    .captures(token)
                    .and_then(|caps| caps.get(1))
                    .is_some_and(|ip| parse_ip(ip.as_str()).is_some())
        };
        let is_ip = |token: &str| parse_ip(token).is_some();

        let split_lines: Vec<Vec<&str>> = samples
            .iter()
            .map(|s| s.split_whitespace().collect())
            .collect();

        let min_len = split_lines.iter().map(|l| l.len()).min().unwrap_or(0);
        if min_len == 0 {
            return Err(anyhow!("Empty sample lines provided"));
        }

        // Class bodies for captured columns. Deliberately loose — the
        // classifier below already proved the training tokens are real
        // addresses, and `IpAddr::from_str` re-checks at parse time.
        const IP_BODY: &str = r"[0-9a-fA-F.:%]+";
        const PORT_BODY: &str = r"\d{1,5}";

        /// What a single column turned out to be, decided before any name is
        /// handed out. See the two-pass comment below for why classification
        /// cannot be fused with emission.
        enum Col {
            /// Same token in every sample: a static anchor, emitted escaped.
            Literal(String),
            Timestamp,
            /// `IP:port` / `IP/port`, where the address half really parses and
            /// the whole token is not itself a valid address — so `2001:db8::1`
            /// and `::443` stay whole bare IPv6 captures. The bool is "uses a
            /// colon".
            IpPort(bool),
            Port,
            Ip,
            Proto,
            Action,
            Opaque,
        }

        // ---- Pass 1: classify every column -------------------------------
        //
        // A capture-group name may appear AT MOST ONCE in a pattern: `Regex::new`
        // rejects duplicates outright, so a second `src_port` does not degrade a
        // capture, it makes the whole pattern uncompilable — and `validate_parser`
        // then rejects the pattern the synthesizer just produced, failing
        // onboarding on a log shape the operator cannot see the problem with.
        let mut kinds: Vec<Col> = Vec::with_capacity(min_len);
        for i in 0..min_len {
            let col: Vec<&str> = split_lines.iter().map(|l| l[i]).collect();
            let all_same = col.windows(2).all(|w| w[0] == w[1]);
            kinds.push(if all_same {
                Col::Literal(regex::escape(col[0]))
            } else if col.iter().all(|t| re_timestamp.is_match(t)) {
                Col::Timestamp
            } else if col.iter().all(|t| is_ip_port(t)) {
                Col::IpPort(col[0].contains(':'))
            } else if col.iter().all(|t| re_port.is_match(t)) {
                Col::Port
            } else if col.iter().all(|t| is_ip(t)) {
                Col::Ip
            } else if col.iter().all(|t| re_proto.is_match(t)) {
                Col::Proto
            } else if col.iter().all(|t| re_action.is_match(t)) {
                Col::Action
            } else {
                Col::Opaque
            });
        }

        // ---- Pass 2: hand out names, priority order ----------------------
        //
        // Names are allocated across ALL columns before a single group is
        // emitted, because the order columns are *seen* is not the order they
        // should be *served*. A bare `443` column and a `10.0.0.1:1000` column
        // both want a port, and if the bare one is served first on sight it
        // takes `dst_port` — leaving the real `10.0.0.2:2000` to be emitted
        // uncaptured, and reporting that unrelated `443` as the destination's
        // port. That is worse than the duplicate-name bug this replaced: the
        // pattern compiles, `validate_parser` passes it (22 is a valid u16), and
        // the store permanently records a wrong endpoint at confidence 1.0.
        //
        // So: endpoint columns claim their slots first, in column order, and
        // standalone port columns fill whatever is left over. A port that cannot
        // be named is emitted uncaptured — a field that is not extracted, which
        // is honest, instead of a field bound to the wrong column, which is not.
        #[derive(Clone, Copy, Default)]
        struct Assigned {
            ip: Option<&'static str>,
            port: Option<&'static str>,
            single: Option<&'static str>,
        }
        let mut assigned = vec![Assigned::default(); min_len];
        const IP_SLOTS: [&str; 2] = ["src_ip", "dst_ip"];
        const PORT_SLOTS: [&str; 2] = ["src_port", "dst_port"];
        // A "side" is an endpoint: an address, and the port that belongs to it.
        //
        // The address cursor and the port cursor are separate, because a bare
        // `443` column and a bare `10.0.0.1` column are INDEPENDENT evidence
        // about side 0 and either can appear without the other:
        //
        //     443  10.0.0.1  80  10.0.0.2      ->  src=10.0.0.1:443  dst=10.0.0.2:80
        //
        // What is not allowed is the two cursors drifting apart on a column that
        // carries BOTH halves. An `IP:port` column is one complete endpoint, and
        // its port must be named from the same side as its address. Free-running
        // cursors let them drift, and the result reports the DESTINATION's port
        // as the source's:
        //
        //     fw  10.0.0.1  10.0.0.2:443
        //         src_ip     dst_ip : src_port   <- wrong side, silently published
        //
        // `port_taken` is what ties them together: a side claimed by an
        // `IP:port` column is off-limits to a later standalone port, so the
        // address and the port on one column can never come from different sides.
        let mut ip_taken = [false; IP_SLOTS.len()];
        let mut port_taken = [false; PORT_SLOTS.len()];

        // Endpoint columns first, in column order.
        for (i, kind) in kinds.iter().enumerate() {
            let complete = matches!(kind, Col::IpPort(_));
            if !complete && !matches!(kind, Col::Ip) {
                continue;
            }
            let Some(side) = (0..IP_SLOTS.len()).find(|s| !ip_taken[*s]) else {
                // No side left, so a complete endpoint yields NEITHER name. A
                // port bound to an address that was not captured is a port on
                // the wrong endpoint, which is the bug this pass exists to stop.
                continue;
            };
            ip_taken[side] = true;
            assigned[i].ip = Some(IP_SLOTS[side]);
            if complete {
                // Unreachable while the standalone pass runs second; guarded
                // anyway, because a reordering would hand `src_port` out twice
                // and duplicate names make the whole pattern uncompilable.
                if !port_taken[side] {
                    port_taken[side] = true;
                    assigned[i].port = Some(PORT_SLOTS[side]);
                }
            }
        }
        // Then standalone port columns, into whatever port sides the endpoints
        // left. A port that cannot be named stays uncaptured — a field that is
        // not extracted, which is honest, rather than one bound to the wrong
        // column.
        for (i, kind) in kinds.iter().enumerate() {
            if !matches!(kind, Col::Port) {
                continue;
            }
            if let Some(side) = (0..PORT_SLOTS.len()).find(|s| !port_taken[*s]) {
                port_taken[side] = true;
                assigned[i].port = Some(PORT_SLOTS[side]);
            }
        }
        // Cosmetic singletons: a repeat is downgraded silently. Missing a
        // second timestamp or an outer protocol name costs a field, not a
        // verdict, so there is nothing to be loud about.
        let mut seen_single: HashSet<&'static str> = HashSet::new();
        for (i, kind) in kinds.iter().enumerate() {
            assigned[i].single = match kind {
                Col::Timestamp => seen_single.insert("timestamp").then_some("timestamp"),
                Col::Proto => seen_single.insert("protocol").then_some("protocol"),
                // NOT downgraded. `action` alone decides `disposition` and
                // `activity_id`, so a second action-bearing column means the
                // line carries two verdicts. Silently keeping one of them turns
                // "these disagree" into a confident single answer — an
                // `ALLOW`/`DENY` conflation. Refusing to guess is the only safe
                // behaviour: onboarding fails loudly with the column index, and
                // the operator supplies samples that do not conflate the fields
                // or writes the parser by hand.
                Col::Action if !seen_single.insert("action") => {
                    return Err(anyhow!(
                        "column {} classifies as an action but column {} already holds \
                         `action`; this format carries two security verdicts per line and a \
                         single `action` capture would report one of them as the disposition. \
                         Remove the ambiguous column from the samples, or define the parser \
                         manually with distinct group names.",
                        i + 1,
                        kinds
                            .iter()
                            .position(|k| matches!(k, Col::Action))
                            .map_or(0, |p| p + 1)
                    ));
                }
                Col::Action => Some("action"),
                _ => None,
            };
        }

        // ---- Pass 3: emit, in column order -------------------------------
        let named = |name: Option<&'static str>, body: &str| -> String {
            match name {
                Some(n) => format!("(?P<{n}>{body})"),
                None => format!("(?:{body})"),
            }
        };
        let mut parts = Vec::with_capacity(min_len);
        for (i, kind) in kinds.iter().enumerate() {
            let a = &assigned[i];
            parts.push(match kind {
                Col::Literal(lit) => lit.clone(),
                Col::Timestamp => named(a.single, r"\S+"),
                Col::IpPort(colon) => {
                    let delim = if *colon { ":" } else { "/" };
                    format!(
                        "{}{delim}{}",
                        named(a.ip, IP_BODY),
                        named(a.port, PORT_BODY)
                    )
                }
                Col::Port => named(a.port, PORT_BODY),
                Col::Ip => named(a.ip, IP_BODY),
                Col::Proto => named(a.single, r"[a-zA-Z0-9]+"),
                Col::Action => named(a.single, r"[a-zA-Z]+"),
                Col::Opaque => r"(?:\S+)".to_string(),
            });
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
        // CEF verbs, mirroring the native CEF extractor's disposition
        // vocabulary (`cef.rs`): without these a synthesized CEF parser maps
        // `act=timeout`/`client-rst`/`server-rst`/`close` to UNKNOWN while the
        // native route reports ALLOWED/CLOSE for the same line.
        map.insert("allowed".to_string(), disposition::ALLOWED.to_string());
        map.insert("close".to_string(), disposition::ALLOWED.to_string());
        map.insert("timeout".to_string(), disposition::ALLOWED.to_string());
        map.insert("client-rst".to_string(), disposition::ALLOWED.to_string());
        map.insert("server-rst".to_string(), disposition::ALLOWED.to_string());
        map.insert("reset".to_string(), disposition::ALLOWED.to_string());
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
    /// Count of registrations whose `regex_pattern` failed to compile. Those
    /// entries are stored but can never parse, so the count is a local
    /// diagnostic: nothing in the serve plane reads it. `GET /parsers` reports
    /// the same condition per-parser, as `status: "invalid"`, which is the
    /// surface an operator actually sees.
    failed_registrations: u64,
}

impl DynamicParserRegistry {
    pub fn new() -> Self {
        Self {
            parsers: BTreeMap::new(),
            clock: 0,
            capacity: REGISTRY_CAPACITY,
            failed_registrations: 0,
        }
    }

    /// Number of parsers registered whose pattern never compiled. Non-zero means
    /// `data/parsers/` holds at least one unusable definition.
    pub fn failed_registrations(&self) -> u64 {
        self.failed_registrations
    }

    fn tick(&mut self) -> u64 {
        self.clock += 1;
        self.clock
    }

    /// Register a new parser definition dynamically. Returns the registry key
    /// (`vendor:device_model`) so callers can install a Tier-1 promotion route.
    ///
    /// An uncompilable `regex_pattern` is counted in [`Self::failed_registrations`]
    /// instead of being silently swallowed: the entry is still stored (so the
    /// key resolves) but its `regex` is `None` and it can never parse, so it must
    /// not be mistaken for a working parser.
    #[must_use = "the registry key is needed to install a promotion route"]
    pub fn register(&mut self, parser: ParserDefinition) -> String {
        let key = format!("{}:{}", parser.vendor.to_lowercase(), parser.device_model);
        let regex = match Regex::new(&parser.regex_pattern) {
            Ok(re) => Some(re),
            Err(_) => {
                self.failed_registrations += 1;
                None
            }
        };
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
    ///
    /// `last_use` is stamped only on a real parse hit. Stamping before the
    /// checks would let a dead entry (uncompilable pattern, or never-matching)
    /// pin itself as most-recently-used and squat a capacity slot forever.
    pub fn parse_key(&mut self, key: &str, raw: &str) -> Option<NetworkActivity> {
        let activity = {
            let entry = self.parsers.get_mut(key)?;
            let re = entry.regex.as_ref()?;
            entry.parser.parse_with_regex(re, raw).ok()?
        };
        // `tick` takes `&mut self`, so stamp the clock first and re-borrow
        // afterwards — the LRU write must not overlap the registry borrow.
        let now = self.tick();
        if let Some(entry) = self.parsers.get_mut(key) {
            entry.last_use = now;
        }
        Some(activity)
    }

    /// Attempt to parse a log line with any registered dynamic parser.
    /// Returns the winning key alongside the event so callers can install a
    /// promotion route; iteration order (BTreeMap) is deterministic.
    pub fn parse_any_keyed(&mut self, raw: &str) -> Option<(String, NetworkActivity)> {
        let mut winner: Option<(String, NetworkActivity)> = None;
        for (key, entry) in self.parsers.iter_mut() {
            if let Some(re) = entry.regex.as_ref() {
                if let Ok(activity) = entry.parser.parse_with_regex(re, raw) {
                    winner = Some((key.clone(), activity));
                    break;
                }
            }
        }
        // Stamp LRU only on a real hit (see `parse_key`).
        let (key, activity) = winner?;
        let now = self.tick();
        if let Some(entry) = self.parsers.get_mut(&key) {
            entry.last_use = now;
        }
        Some((key, activity))
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

/// Alias a JSON leaf key to its canonical capture name.
///
/// Covers Suricata EVE spellings (`src_ip`, `dest_ip`, `dest_port`) and the
/// short forms other JSON emitters use (`srcip`, `dstip`, `dport`, `act`).
/// Anything unlisted returns `None` and is left out of the pattern.
fn json_alias(leaf: &str) -> Option<&'static str> {
    match leaf.to_ascii_lowercase().as_str() {
        "src_ip" | "srcip" | "source_ip" | "src" => Some("src_ip"),
        "dest_ip" | "dstip" | "dest" | "dst_ip" | "dst" => Some("dst_ip"),
        "src_port" | "sport" | "source_port" => Some("src_port"),
        "dest_port" | "dport" | "destport" | "dst_port" | "dstport" => Some("dst_port"),
        "proto" | "protocol" | "transport" => Some("protocol"),
        "action" | "act" => Some("action"),
        _ => None,
    }
}

/// Look up a key path in a JSON document. Returns `Some((is_str, is_num))`
/// for scalar string/number leaves, `None` when the path is absent (or is
/// not a scalar — a type change across samples counts as absent, so the
/// clause degrades to optional rather than trusting one shape).
fn json_path_scalar(value: &serde_json::Value, path: &[String]) -> Option<(bool, bool)> {
    let mut cur = value;
    for seg in path {
        cur = cur.as_object()?.get(seg)?;
    }
    if cur.is_string() {
        Some((true, false))
    } else if cur.is_number() {
        Some((false, true))
    } else {
        None
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

/// Parse a log-captured address into an `IpAddr`, accepting both IPv4 and IPv6.
///
/// Strips an RFC 4007 zone id (`fe80::1%eth0`) before parsing: the synthesized
/// patterns admit `%` so link-local samples capture cleanly, but
/// `IpAddr::from_str` does not accept a scoped address. Returns `None` for
/// anything that is not a valid address.
fn parse_ip(raw: &str) -> Option<IpAddr> {
    let trimmed = raw.trim();
    let unscoped = trimmed.split_once('%').map_or(trimmed, |(addr, _)| addr);
    IpAddr::from_str(unscoped).ok()
}

/// Compile a hard-coded synthesizer pattern. These literals are
/// regression-tested, but `Regex::new` still returns `Result` — propagate it
/// with `?` instead of `unwrap()` so a future typo in a literal surfaces as a
/// diagnosable `Err` from `generate_parser`, never a panic on the onboard path.
fn static_re(pattern: &str) -> Result<Regex> {
    Regex::new(pattern).with_context(|| format!("Invalid hard-coded regex: {pattern}"))
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

    /// A capture-group name may appear at most once per pattern. `Regex::new`
    /// rejects duplicates outright, so a repeat does not degrade a capture — it
    /// makes the pattern uncompilable, and `validate_parser` then rejects the
    /// pattern the synthesizer just produced.
    ///
    /// Each case is a real log shape whose columns collide on a name, either
    /// because two columns of one kind compete, or because two *kinds* compete
    /// for the same slot.
    #[test]
    fn test_positional_synthesizer_never_emits_duplicate_group_names() {
        // Each case: (label, samples). Names that carry no security meaning
        // (`timestamp`, `protocol`) may be silently downgraded; a name that
        // does (`action`) is a hard error and is covered by its own test.
        let cases: Vec<(&str, Vec<&str>)> = vec![
            (
                "standalone port column, then addr:port columns",
                vec![
                    "host 443 10.0.0.1:1000 10.0.0.2:2000 TCP accept",
                    "host 444 10.0.0.3:1001 10.0.0.4:2001 TCP accept",
                    "host 445 10.0.0.5:1002 10.0.0.6:2002 TCP accept",
                ],
            ),
            (
                "addr:port column, then a standalone port column",
                vec![
                    "10.0.0.1:1000 22 10.0.0.2:2000 TCP accept",
                    "10.0.0.3:1001 23 10.0.0.4:2001 TCP accept",
                    "10.0.0.5:1002 24 10.0.0.6:2002 TCP accept",
                ],
            ),
            (
                "two varying date columns",
                vec![
                    "2026-09-21 2026-09-22 10.0.0.1 10.0.0.2 TCP accept",
                    "2026-09-23 2026-09-24 10.0.0.3 10.0.0.4 TCP accept",
                    "2026-09-25 2026-09-26 10.0.0.5 10.0.0.6 TCP accept",
                ],
            ),
            (
                "two varying protocol columns",
                vec![
                    "10.0.0.1 10.0.0.2 ESP AH accept",
                    "10.0.0.3 10.0.0.4 TCP GRE accept",
                    "10.0.0.5 10.0.0.6 UDP ESP accept",
                ],
            ),
            (
                "three bare ip columns, so the third has no slot",
                vec![
                    "10.0.0.1 10.0.0.2 10.0.0.3 443 TCP accept",
                    "10.0.0.4 10.0.0.5 10.0.0.6 444 TCP accept",
                    "10.0.0.7 10.0.0.8 10.0.0.9 445 TCP accept",
                ],
            ),
        ];

        for (label, samples) in cases {
            let pattern =
                Onboarder::synthesize_regex(&samples).unwrap_or_else(|e| panic!("{label}: {e}"));
            let re = Regex::new(&pattern).unwrap_or_else(|e| {
                panic!("{label} produced an uncompilable pattern: {e}\n  {pattern}")
            });
            // Belt and braces: a name that survives `Regex::new` is unique by
            // construction, so assert the invariant at the boundary rather
            // than trusting the allocator.
            let mut seen = std::collections::HashSet::new();
            for n in re.capture_names().flatten() {
                assert!(
                    seen.insert(n),
                    "{label}: capture name {n:?} appears more than once in {pattern}"
                );
            }
            // Compiling is not enough — the pattern must also survive the
            // validator, or onboarding fails on the user's own samples.
            let def = ParserDefinition {
                vendor: "v".into(),
                device_model: "m".into(),
                regex_pattern: pattern,
                action_mappings: HashMap::new(),
                sample_logs: vec![],
                confidence_score: 1.0,
                created_at: 0,
                schema_version: 0,
                regex_cache: Arc::new(OnceLock::new()),
            };
            let report = Onboarder::validate_parser(&def, &samples)
                .unwrap_or_else(|e| panic!("{label}: validator errored: {e}"));
            assert!(
                report.passed,
                "{label}: pattern must validate against its own samples: {:?}",
                report.errors
            );
        }
    }

    /// A port name must never be bound to a column it does not describe.
    ///
    /// This is the failure the first cut of the duplicate-name fix introduced,
    /// and it is worse than the bug it replaced. Serving columns in sight-order
    /// meant a bare `22` seen between two `IP:port` columns claimed `dst_port`,
    /// while the real `10.0.0.2:2000` was emitted uncaptured. The pattern then
    /// COMPILED, `validate_parser` accepted it (22 is a valid u16), and the
    /// definition was published at `confidence_score: 1.0` reporting
    /// `dst_port = 22` for an endpoint whose port is 2000. A duplicate name was
    /// a loud onboarding failure; this is a permanent, confident, wrong fact in
    /// the store.
    ///
    /// Endpoint columns therefore claim their slots first, and a standalone
    /// port that cannot be named is left uncaptured — a field that is not
    /// extracted, which is honest, rather than one bound to the wrong column.
    #[test]
    fn test_positional_port_names_bind_to_the_column_they_describe() {
        // The standalone `22` / `23` / `24` column is an unrelated field. It must
        // not be reported as the destination port.
        let samples = vec![
            "10.0.0.1:1000 22 10.0.0.2:2000 TCP accept",
            "10.0.0.3:1001 23 10.0.0.4:2001 TCP accept",
            "10.0.0.5:1002 24 10.0.0.6:2002 TCP accept",
        ];
        let pattern = Onboarder::synthesize_regex(&samples).unwrap();
        let re = Regex::new(&pattern).unwrap();
        let caps = re.captures(samples[0]).unwrap();
        let got = |n: &str| caps.name(n).map(|m| m.as_str().to_string());

        assert_eq!(got("src_ip").as_deref(), Some("10.0.0.1"));
        assert_eq!(
            got("src_port").as_deref(),
            Some("1000"),
            "src_port must be the port from the source's own addr:port column"
        );
        assert_eq!(got("dst_ip").as_deref(), Some("10.0.0.2"));
        assert_eq!(
            got("dst_port").as_deref(),
            Some("2000"),
            "dst_port must be the port from the DESTINATION's addr:port column, \
             never an unrelated standalone port column"
        );

        // And the symmetric case: standalone ports on BOTH sides of two
        // addr:port columns. Both standalone columns go uncaptured; neither
        // endpoint's real port is displaced.
        let samples = vec![
            "443 10.0.0.1:1000 80 10.0.0.2:2000 TCP accept",
            "444 10.0.0.3:1001 81 10.0.0.4:2001 TCP accept",
            "445 10.0.0.5:1002 82 10.0.0.6:2002 TCP accept",
        ];
        let caps = Regex::new(&Onboarder::synthesize_regex(&samples).unwrap())
            .unwrap()
            .captures(samples[0])
            .unwrap();
        let got = |n: &str| caps.name(n).map(|m| m.as_str().to_string());
        assert_eq!(got("src_port").as_deref(), Some("1000"));
        assert_eq!(got("dst_port").as_deref(), Some("2000"));
    }

    /// The address and the port on ONE column must come from the same side.
    ///
    /// A sibling of the test above, one level deeper. Fixing that one required
    /// independent ip/port cursors, and two independent cursors can drift: a
    /// bare `10.0.0.1` column claims address-side 0 while a later
    /// `10.0.0.2:443` column reads port-side 0, so the DESTINATION's port is
    /// recorded as the source's. It compiles, `validate_parser` accepts it (443
    /// is a valid u16), and it publishes at confidence 1.0:
    ///
    ///     fw  10.0.0.1  10.0.0.2:443
    ///         src_ip     dst_ip : src_port   <- 443 is the destination's
    ///
    /// An `IP:port` column is one complete endpoint, so both of its names are
    /// taken from a single side index. The cursors stay separate — a bare
    /// `443` and a bare `10.0.0.1` are independent evidence and either can
    /// appear alone — but a side claimed by an `IP:port` column is off-limits
    /// to a later standalone port, which is what stops the drift.
    #[test]
    fn test_positional_addr_port_column_takes_both_names_from_one_side() {
        // (1) An `IP` column takes address-side 0; the `IP:port` column that
        //     follows must take address-side 1 AND port-side 1.
        let samples = vec![
            "fw 10.0.0.1 10.0.0.2:443 TCP accept",
            "fw 10.0.0.3 10.0.0.4:444 TCP accept",
            "fw 10.0.0.5 10.0.0.6:445 TCP accept",
        ];
        let pattern = Onboarder::synthesize_regex(&samples).unwrap();
        let re = Regex::new(&pattern).unwrap();
        let caps = re.captures(samples[0]).unwrap();
        let got = |n: &str| caps.name(n).map(|m| m.as_str().to_string());

        assert_eq!(got("src_ip").as_deref(), Some("10.0.0.1"));
        assert_eq!(got("dst_ip").as_deref(), Some("10.0.0.2"));
        assert_eq!(
            got("dst_port").as_deref(),
            Some("443"),
            "443 is the destination's port: {pattern}"
        );
        assert_eq!(
            got("src_port"),
            None,
            "the source column has no port, so src_port must be absent rather \
             than hold the destination's: {pattern}"
        );

        // (2) No address side left: the `IP:port` column yields NEITHER name.
        // A port bound to an uncaptured address is a port on an endpoint that
        // was never identified, which is the same wrong fact in a new place.
        let samples = vec![
            "10.0.0.1 10.0.0.2 10.0.0.3:443 TCP accept",
            "10.0.0.4 10.0.0.5 10.0.0.6:444 TCP accept",
            "10.0.0.7 10.0.0.8 10.0.0.9:445 TCP accept",
        ];
        let pattern = Onboarder::synthesize_regex(&samples).unwrap();
        let re = Regex::new(&pattern).unwrap();
        let caps = re.captures(samples[0]).unwrap();
        let got = |n: &str| caps.name(n).map(|m| m.as_str().to_string());

        assert_eq!(got("src_ip").as_deref(), Some("10.0.0.1"));
        assert_eq!(got("dst_ip").as_deref(), Some("10.0.0.2"));
        assert_eq!(
            got("src_port"),
            None,
            "the third column has no address side, so it gets no port name: {pattern}"
        );
        assert_eq!(
            got("dst_port"),
            None,
            "the third column has no address side, so it gets no port name: {pattern}"
        );
    }

    /// A standalone port column still fills a slot when nothing else wants it.
    ///
    /// The counterpart to the test above: the priority pass must not *starve*
    /// standalone ports. In `443 10.0.0.1 80 10.0.0.2` there is no addr:port
    /// column at all, so the two bare ports are the only port evidence and must
    /// be captured rather than dropped.
    #[test]
    fn test_positional_standalone_ports_are_captured_when_nothing_else_claims_the_slot() {
        let samples = vec![
            "443 10.0.0.1 80 10.0.0.2 TCP accept",
            "444 10.0.0.3 81 10.0.0.4 TCP accept",
            "445 10.0.0.5 82 10.0.0.6 TCP accept",
        ];
        let pattern = Onboarder::synthesize_regex(&samples).unwrap();
        let caps = Regex::new(&pattern).unwrap().captures(samples[0]).unwrap();
        let got = |n: &str| caps.name(n).map(|m| m.as_str().to_string());
        assert_eq!(got("src_port").as_deref(), Some("443"));
        assert_eq!(got("src_ip").as_deref(), Some("10.0.0.1"));
        assert_eq!(got("dst_port").as_deref(), Some("80"));
        assert_eq!(got("dst_ip").as_deref(), Some("10.0.0.2"));
    }

    /// Two action-bearing columns must REFUSE to onboard, not pick one.
    ///
    /// `action` alone determines `disposition` and `activity_id`. A line
    /// carrying two verdicts (`accept deny`) cannot be represented by one
    /// capture, and silently keeping the first turns "these disagree" into a
    /// confident single answer — an `ALLOW`/`DENY` conflation, which is the one
    /// direction of error this framework must never take silently. Onboarding
    /// failing loudly, with both column indices named, is the safe outcome: the
    /// operator can disambiguate the samples or write the parser by hand.
    ///
    /// This is deliberately NOT symmetric with `protocol` or `timestamp`. Those
    /// cost a field; this costs a verdict.
    #[test]
    fn test_positional_two_action_columns_fail_loudly_rather_than_pick_one() {
        let samples = vec![
            "10.0.0.1 10.0.0.2 TCP accept deny",
            "10.0.0.3 10.0.0.4 TCP drop block",
            "10.0.0.5 10.0.0.6 TCP pass reject",
        ];
        let err = Onboarder::synthesize_regex(&samples)
            .expect_err("two security verdicts must not collapse into one `action` capture");
        let msg = err.to_string();
        // The message has to be actionable: which two columns, and what to do.
        assert!(
            msg.contains("column 5"),
            "must name the second column: {msg}"
        );
        assert!(
            msg.contains("column 4"),
            "must name the first column: {msg}"
        );
        assert!(
            msg.contains("action"),
            "must name the contended capture: {msg}"
        );

        // And it must not be reachable through the public entry point either.
        let err = Onboarder::generate_parser("vendor", "model", &samples)
            .expect_err("generate_parser must surface the refusal");
        assert!(
            err.to_string().contains("action"),
            "the public API must carry the reason: {err}"
        );
    }

    /// Every emitting branch of the synthesizer must produce a compilable
    /// pattern with unique capture names.
    ///
    /// The name budget protects `synthesize_positional_regex` only. The flow
    /// and key-value synthesizers hand-write their groups and rely on being
    /// duplicate-free by inspection, and `static_re` is applied to their probe
    /// patterns but never to the literals they emit. That is exactly the kind
    /// of invariant that a future edit reintroduces the original bug through —
    /// adding `(?P<action>...)` to a flow pattern that already emits
    /// `(?P<action_verb>...)`, for instance. Pinning it here means the check
    /// does not depend on anyone having read every branch.
    #[test]
    fn test_no_synthesizer_branch_emits_a_duplicate_capture_name() {
        let cases: Vec<(&str, Vec<&str>)> = vec![
            (
                "positional",
                vec![
                    "host 443 10.0.0.1:1000 10.0.0.2:2000 TCP accept",
                    "host 444 10.0.0.3:1001 10.0.0.4:2001 TCP accept",
                ],
            ),
            (
                "key-value",
                vec![
                    "action=accept src=10.0.0.1 dst=10.0.0.2 sport=1234 dport=443 proto=tcp",
                    "action=deny src=10.0.0.3 dst=10.0.0.4 sport=1235 dport=80 proto=udp",
                ],
            ),
            (
                "flow with -> arrow",
                vec![
                    "10.0.0.1 -> 10.0.0.2 proto=TCP action=accept",
                    "10.0.0.3 -> 10.0.0.4 proto=UDP action=deny",
                ],
            ),
            (
                "flow with colon separator",
                vec![
                    "10.0.0.1: 10.0.0.2 TCP allow",
                    "10.0.0.3: 10.0.0.4 UDP deny",
                ],
            ),
            (
                "flow with slash separator",
                vec!["10.0.0.1/10.0.0.2 TCP allow", "10.0.0.3/10.0.0.4 UDP deny"],
            ),
        ];

        for (label, samples) in cases {
            let pattern = Onboarder::synthesize_regex(&samples)
                .unwrap_or_else(|e| panic!("{label}: {e}\n  samples: {samples:?}"));
            let re = Regex::new(&pattern).unwrap_or_else(|e| {
                panic!("{label} produced an uncompilable pattern: {e}\n  {pattern}")
            });
            let mut seen = std::collections::HashSet::new();
            for n in re.capture_names().flatten() {
                assert!(
                    seen.insert(n),
                    "{label}: capture name {n:?} appears more than once\n  {pattern}"
                );
            }
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
            schema_version: 0,
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

    /// Runtime extraction stays consistent with validation: a bare IPv6
    /// address captured as `src_ip`/`dst_ip` parses intact (no IPv4-only
    /// assumption may mangle or reject it), while a non-address in an
    /// endpoint capture is an Err — the same verdict `validate_parser`
    /// renders for that sample.
    #[test]
    fn test_parse_runtime_validates_endpoint_captures() {
        let parser = ParserDefinition {
            vendor: "test".into(),
            device_model: "v6rt".into(),
            regex_pattern: r"^src=(?P<src_ip>\S+) dst=(?P<dst_ip>\S+)$".to_string(),
            action_mappings: HashMap::new(),
            sample_logs: vec![],
            confidence_score: 1.0,
            created_at: 0,
            schema_version: 0,
            regex_cache: Arc::new(OnceLock::new()),
        };
        let ev = parser.parse("src=2001:db8::1 dst=::443").unwrap();
        assert_eq!(ev.src_endpoint.ip.as_deref(), Some("2001:db8::1"));
        assert_eq!(ev.dst_endpoint.ip.as_deref(), Some("::443"));

        // A wall-clock fragment in an endpoint capture must not file an
        // event under a garbage IP.
        let err = parser
            .parse("src=14:00 dst=10.0.0.2")
            .expect_err("non-address src_ip must Err, like a validation miss");
        assert!(
            err.to_string().contains("Invalid src_ip"),
            "error must name the bad capture: {err}"
        );
        assert!(
            parser.parse("src=10.0.0.1 dst=not-an-ip").is_err(),
            "non-address dst_ip must Err too"
        );
        // Repeated bad-capture events stay Err, never panic.
        assert!(parser.parse("src=14:00 dst=10.0.0.2").is_err());
    }

    /// Compiled regex is cached via Arc<OnceLock<Result<Regex, Error>>> — repeated
    /// parse() calls must NOT recompile. Asserted on the cache itself, not just
    /// on results.
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
            schema_version: 0,
            regex_cache: Arc::new(OnceLock::new()),
        };
        // First parse compiles + initializes the OnceLock.
        let ev1 = parser.parse("src=10.0.0.1 dst=10.0.0.2").unwrap();
        let ev2 = parser.parse("src=10.0.0.3 dst=10.0.0.4").unwrap();
        assert_eq!(ev1.src_endpoint.ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(ev2.src_endpoint.ip.as_deref(), Some("10.0.0.3"));
        let cached = parser
            .regex_cache
            .get()
            .expect("cache must be initialized after the first parse")
            .as_ref()
            .expect("cached compile must be Ok for a valid pattern");
        assert!(
            cached.is_match("src=10.0.0.9 dst=10.0.0.8"),
            "the cached Regex must be the live one used by parse()"
        );

        // A Clone gets a FRESH cell, never the warm one: `regex_pattern` is
        // public, so a clone may re-pattern itself. Sharing would make the
        // clone parse with the ORIGINAL pattern while to_json/to_yaml serialize
        // the new one — a silent correctness bug, not a cache hit.
        let mut cloned = parser.clone();
        assert!(
            !Arc::ptr_eq(&parser.regex_cache, &cloned.regex_cache),
            "Clone must NOT inherit a warm cache cell from the original"
        );
        cloned.regex_pattern = r"^src=(?P<src_ip>\S+) only=(?P<dst_ip>\S+)$".to_string();
        let ev3 = cloned.parse("src=10.0.0.5 only=10.0.0.6").unwrap();
        assert_eq!(ev3.src_endpoint.ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(
            ev3.dst_endpoint.ip.as_deref(),
            Some("10.0.0.6"),
            "the clone must use ITS OWN pattern, not the original's"
        );
        assert!(
            cloned.parse("src=10.0.0.5 dst=10.0.0.6").is_err(),
            "the original pattern must not leak into the re-patterned clone"
        );
        // The original is untouched by the clone's divergence.
        assert!(parser.parse("src=10.0.0.7 dst=10.0.0.8").is_ok());
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
            schema_version: 0,
            regex_cache: Arc::new(OnceLock::new()),
        };
        // Must not panic — a Result-returning pub fn must surface Err.
        let err = parser
            .parse("src=10.0.0.1")
            .expect_err("invalid regex must Err, not panic");
        let msg = err.to_string();
        assert!(
            msg.contains("Invalid compiled regex"),
            "error must name the compile failure: {msg}"
        );
        // The CACHED error must stay diagnosable: an `Option` cell would have
        // collapsed this to a bare "no regex" with no cause on every event.
        assert!(
            msg.contains("unclosed"),
            "error must carry the underlying regex::Error cause: {msg}"
        );
        // Repeat call must stay Err with the same cause (cache stores the
        // failure, not panics).
        let err2 = parser.parse("src=10.0.0.1").expect_err("still Err");
        assert_eq!(err2.to_string(), msg, "cached failure must be stable");
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
            schema_version: 0,
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

    /// Backwards compatibility with files already on disk.
    ///
    /// The round-trip test above only proves the NEW emitter and NEW loader
    /// agree with each other, which is worthless if every parser published by a
    /// previous release stops loading. This pins the two shapes that exist in
    /// the wild: the output of the hand-rolled emitter this PR replaced, and
    /// `to_json` output, which the old loader accepted as "YAML" because it
    /// tried `serde_json` first.
    ///
    /// The legacy fixture is the old emitter's output verbatim — double-quoted
    /// scalars, 2-decimal `confidence_score`, bare integer `created_at`,
    /// `sample_logs` as a quoted list.
    ///
    /// `regex_pattern` carries a backslash, which every synthesized pattern
    /// does. Note the `\\\\` in the Rust literal below: the old emitter doubled
    /// backslashes when writing, and a YAML double-quoted scalar needs the
    /// doubling to survive — a bare `\d` there is an *invalid escape* and no
    /// YAML parser can read the file. The loader has to turn `\\d` back into
    /// `\d` or it loads a different regex than the one on disk.
    #[test]
    fn test_from_yaml_loads_legacy_emitter_output_and_json() {
        let legacy = concat!(
            "vendor: \"Fortinet\"\n",
            "device_model: \"FortiGate\"\n",
            "confidence_score: 1.00\n",
            "created_at: 1700000000000\n",
            "regex_pattern: \"^src=(?P<src_ip>[0-9.]+) dst=(?P<dst_port>\\\\d{1,5})$\"\n",
            "action_mappings:\n",
            "  pass: \"Allowed\"\n",
            "  deny: \"Blocked\"\n",
            "sample_logs:\n",
            "  - \"src=10.0.0.1 dst=22\"\n",
            "  - \"src=10.0.0.3 dst=443\"\n",
        );
        let def = ParserDefinition::from_yaml(legacy)
            .expect("a YAML file published by a previous release must still load");
        assert_eq!(def.vendor, "Fortinet");
        assert_eq!(def.device_model, "FortiGate");
        // The doubled backslash in the file must decode to ONE backslash, or
        // the loaded pattern is a different regex from the one on disk.
        assert_eq!(
            def.regex_pattern,
            r"^src=(?P<src_ip>[0-9.]+) dst=(?P<dst_port>\d{1,5})$"
        );
        assert_eq!(
            def.action_mappings.get("deny").map(String::as_str),
            Some("Blocked")
        );
        assert_eq!(def.sample_logs.len(), 2);
        assert!((def.confidence_score - 1.0).abs() < f64::EPSILON);
        assert_eq!(def.created_at, 1_700_000_000_000);
        // And it must be usable, not merely parseable.
        let ev = def
            .parse("src=10.0.0.1 dst=22")
            .expect("a legacy-loaded definition must still parse");
        assert_eq!(ev.src_endpoint.ip.as_deref(), Some("10.0.0.1"));
        assert_eq!(ev.dst_endpoint.port, Some(22));

        // `to_json` output is valid YAML, and the old loader relied on that.
        let json = def.to_json().unwrap();
        let from_json_as_yaml = ParserDefinition::from_yaml(&json)
            .expect("JSON is a YAML subset; from_yaml must keep accepting it");
        assert_eq!(from_json_as_yaml.regex_pattern, def.regex_pattern);
        assert_eq!(from_json_as_yaml.sample_logs, def.sample_logs);
    }

    /// A sample log containing backslashes must survive the YAML round trip
    /// BYTE-FOR-BYTE.
    ///
    /// The emitter this replaced hand-escaped `sample_logs` with only
    /// `replace('"', "\\\"")`, so a backslash was written raw into a
    /// double-quoted YAML scalar — where it is an *escape*, not a literal. Two
    /// distinct failures follow, both observed against a real YAML parser:
    ///
    /// - SILENT CORRUPTION: `C:\temp\fw.log` comes back as `C:<TAB>emp<CR>fw.log`,
    ///   because `\t` and `\r` are valid escapes. The file parses fine and the
    ///   stored sample is simply wrong — the worst outcome, since nothing fails.
    /// - HARD REJECTION: `C:\data\fw.log` and `proto=T \d denied` produce a
    ///   document no YAML parser will read, because `\d` is not an escape at all.
    ///
    /// `regex_pattern` was escaped correctly; only `sample_logs` was not. The
    /// first assertion is the load-bearing one — a serializer that round-trips
    /// is the only thing standing between a Windows firewall path and a
    /// quietly altered training sample.
    #[test]
    fn test_yaml_roundtrip_preserves_backslashes_in_sample_logs() {
        let samples = vec![
            r"C:\temp\fw.log blocked".to_string(),
            r"proto=T \d denied".to_string(),
            r#"tab\there and "quoted""#.to_string(),
            r#"trailing backslash \"#.to_string(),
            String::new(),
            r"a\b\c\d\e\f\g".to_string(),
        ];
        let parser = ParserDefinition {
            vendor: "windows".into(),
            device_model: "wf".into(),
            // Also carries a backslash, exercising the other escaping path.
            regex_pattern: r"^src=(?P<src_ip>\S+)$".to_string(),
            action_mappings: HashMap::from([("deny".to_string(), "Blocked".to_string())]),
            sample_logs: samples.clone(),
            confidence_score: 0.97,
            created_at: 1_700_000_000_000,
            schema_version: 0,
            regex_cache: Arc::new(OnceLock::new()),
        };

        let yaml = parser.to_yaml().unwrap();
        let back = ParserDefinition::from_yaml(&yaml)
            .unwrap_or_else(|e| panic!("emitted YAML must be loadable: {e:#}\n---\n{yaml}"));

        assert_eq!(
            back.sample_logs, samples,
            "sample_logs must round-trip byte-for-byte; the emitted YAML was:\n{yaml}"
        );
        assert_eq!(back.regex_pattern, parser.regex_pattern);
        assert_eq!(back.action_mappings, parser.action_mappings);
    }

    /// A file missing fields now FAILS LOUDLY instead of loading as a dead
    /// parser.
    ///
    /// The old loader defaulted every absent field, so `vendor: "Acme"` alone
    /// produced a definition with an EMPTY `regex_pattern` — a parser that
    /// matched nothing, was served by `GET /parsers` as active, and was
    /// registered into the hot path. Rejecting the file is the point; the
    /// machine-readable message is what makes it fixable.
    #[test]
    fn test_from_yaml_rejects_partial_definition_instead_of_defaulting() {
        let err = ParserDefinition::from_yaml("vendor: \"Acme\"\n")
            .expect_err("a definition with no regex_pattern must not load");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("missing field"),
            "the error must name the missing field so it can be fixed: {msg}"
        );
        // Any of the six absent fields is a valid diagnosis — the point is that
        // it is reported, not which one comes first in the struct.
        assert!(
            [
                "device_model",
                "regex_pattern",
                "action_mappings",
                "sample_logs"
            ]
            .iter()
            .any(|f| msg.contains(f)),
            "error must name a field that is actually absent: {msg}"
        );
        // The anyhow context chain must survive: a bare "invalid YAML" is not
        // actionable, the inner serde message is.
        assert!(
            msg.contains("ParserDefinition"),
            "error must identify the type being deserialized: {msg}"
        );
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
            schema_version: 0,
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
        assert!(
            !report.errors.is_empty(),
            "the failed sample must surface as a warning, not vanish"
        );
        assert_eq!(report.matched_samples, 19);
        assert_eq!(report.total_samples, 20);
    }

    /// confidence_score must reflect the real match percentage, not a hardcoded
    /// 1.0. Driven with a genuinely PARTIAL run (19/20 = 0.95) so the assertion
    /// fails against the old `confidence_score: 1.0`.
    #[test]
    fn test_confidence_score_reflects_match_percentage() {
        let mut owned: Vec<String> = (0..19)
            .map(|i| format!("srcip=10.1.1.{i} dstip=10.2.2.2 action=pass"))
            .collect();
        owned.push("garbage that will not match".to_string());
        let samples: Vec<&str> = owned.iter().map(|s| s.as_str()).collect();

        let (def, report) = Onboarder::generate_parser("v", "m", &samples).unwrap();
        assert_eq!(report.match_percentage, 95.0);
        assert!(
            (def.confidence_score - 0.95).abs() < 1e-9,
            "confidence must be 0.95 for a 95% run, not 1.0: got {}",
            def.confidence_score
        );
    }

    /// Below 20 samples the gate stays STRICT: at N=3 a single failure is 33%,
    /// which is not a 95% rule. `max(1)` used to pass it.
    #[test]
    fn test_threshold_strict_below_20_samples() {
        let parser = ParserDefinition {
            vendor: "test".into(),
            device_model: "small".into(),
            regex_pattern: r"^srcip=(?P<src_ip>\S+) dstip=(?P<dst_ip>\S+)$".to_string(),
            action_mappings: HashMap::new(),
            sample_logs: vec![],
            confidence_score: 1.0,
            created_at: 0,
            schema_version: 0,
            regex_cache: Arc::new(OnceLock::new()),
        };
        // 2 of 3 match = 66.7% — must FAIL below the relaxation floor.
        let samples = [
            "srcip=10.0.0.1 dstip=10.0.0.2",
            "srcip=10.0.0.3 dstip=10.0.0.4",
            "total garbage that cannot match",
        ];
        let report = Onboarder::validate_parser(&parser, &samples).unwrap();
        assert!(
            !report.passed,
            "66.7% must not pass below 20 samples: {:?}",
            report.errors
        );
    }

    /// A dead entry (uncompilable pattern) must not pin itself as
    /// most-recently-used and squat a capacity slot forever.
    #[test]
    fn test_dead_entry_does_not_pin_lru_slot() {
        let mut reg = DynamicParserRegistry::new();
        let dead = ParserDefinition {
            vendor: "deadvendor".into(),
            device_model: "broken".into(),
            regex_pattern: "^(?P<src_ip>[unclosed".to_string(),
            action_mappings: HashMap::new(),
            sample_logs: vec![],
            confidence_score: 1.0,
            created_at: 0,
            schema_version: 0,
            regex_cache: Arc::new(OnceLock::new()),
        };
        assert_eq!(reg.register(dead), "deadvendor:broken");
        assert_eq!(
            reg.failed_registrations(),
            1,
            "uncompilable pattern must be counted, not silently swallowed"
        );
        assert!(
            reg.parse_key("deadvendor:broken", "anything").is_none(),
            "dead entry can never parse"
        );
        // Fill the registry, then overflow: the dead entry must be evicted
        // (it was never successfully used) rather than surviving forever.
        let mk = |m: &str| ParserDefinition {
            vendor: "v".into(),
            device_model: m.into(),
            regex_pattern: r"^line (?P<src_port>\d+)$".to_string(),
            action_mappings: HashMap::new(),
            sample_logs: vec![],
            confidence_score: 1.0,
            created_at: 0,
            schema_version: 0,
            regex_cache: Arc::new(OnceLock::new()),
        };
        for i in 0..REGISTRY_CAPACITY {
            let _ = reg.register(mk(&format!("m-{i:04}")));
        }
        // Touch the last live entry so it is NOT the eviction victim.
        let last = format!("v:m-{:04}", REGISTRY_CAPACITY - 1);
        assert!(reg.parse_key(&last, "line 443").is_some());
        let _ = reg.register(mk("overflow"));
        assert_eq!(reg.len(), REGISTRY_CAPACITY, "bound must hold");
        assert!(
            !reg.parsers.contains_key("deadvendor:broken"),
            "a never-parsing entry must age out under LRU pressure, not pin a slot"
        );
    }

    /// Positional synthesis must capture ports that appear in their own
    /// columns — the loose IP class also matches digits, so branch order matters.
    #[test]
    fn test_positional_synthesizer_standalone_port_columns() {
        let samples = vec![
            "edge 10.0.0.1 10.0.0.2 443 22 TCP accept",
            "edge 10.0.0.3 10.0.0.4 444 23 TCP accept",
            "edge 10.0.0.5 10.0.0.6 445 24 TCP accept",
        ];
        let pattern = Onboarder::synthesize_regex(&samples).unwrap();
        let re = Regex::new(&pattern).unwrap();
        let caps = re.captures(samples[0]).unwrap();
        assert_eq!(caps.name("src_ip").map(|m| m.as_str()), Some("10.0.0.1"));
        assert_eq!(caps.name("dst_ip").map(|m| m.as_str()), Some("10.0.0.2"));
        assert_eq!(
            caps.name("src_port").map(|m| m.as_str()),
            Some("443"),
            "standalone port column must be captured, not swallowed by the IP branch"
        );
        assert_eq!(caps.name("dst_port").map(|m| m.as_str()), Some("22"));
    }

    /// Zero evaluated samples must FAIL. `0 == 0` reported a vacuous pass with a
    /// 0.0% match rate — the worst possible outcome for a validation gate.
    #[test]
    fn test_threshold_fails_with_zero_samples() {
        let parser = ParserDefinition {
            vendor: "test".into(),
            device_model: "empty".into(),
            regex_pattern: r"^srcip=(?P<src_ip>\S+) dstip=(?P<dst_ip>\S+)$".to_string(),
            action_mappings: HashMap::new(),
            sample_logs: vec![],
            confidence_score: 1.0,
            created_at: 0,
            schema_version: 0,
            regex_cache: Arc::new(OnceLock::new()),
        };
        for empty in [vec![], vec!["", "   ", "\t"]] {
            let report = Onboarder::validate_parser(&parser, &empty).unwrap();
            assert_eq!(report.total_samples, 0);
            assert!(
                !report.passed,
                "a parser validated against {empty:?} must not be admitted"
            );
        }
    }

    /// Two date columns (start/end) must not emit two `timestamp` groups —
    /// duplicate capture names make the pattern fail to compile, so the
    /// synthesized parser would be rejected by its own validator.
    #[test]
    fn test_positional_synthesizer_two_date_columns_compile() {
        let samples = vec![
            "2026-09-21 2026-09-22 10.0.0.1 10.0.0.2 TCP accept",
            "2026-09-23 2026-09-24 10.0.0.3 10.0.0.4 TCP accept",
            "2026-09-25 2026-09-26 10.0.0.5 10.0.0.6 TCP accept",
        ];
        let pattern = Onboarder::synthesize_regex(&samples).unwrap();
        let re = Regex::new(&pattern).expect("pattern with 2 date columns must compile");
        let caps = re.captures(samples[0]).unwrap();
        assert_eq!(
            caps.name("timestamp").map(|m| m.as_str()),
            Some("2026-09-21"),
            "the FIRST date column takes the named group"
        );
        assert_eq!(caps.name("src_ip").map(|m| m.as_str()), Some("10.0.0.1"));
        assert_eq!(caps.name("dst_ip").map(|m| m.as_str()), Some("10.0.0.2"));
    }

    /// A wall-clock column is not an address. The permissive `[0-9a-fA-F.:%]+`
    /// class also matches `14:00:01`, so a positional log with an HH:MM:SS
    /// column was synthesized as `src_ip=14:00` + `src_port=01` and then failed
    /// its own validation.
    #[test]
    fn test_positional_synthesizer_wall_clock_column_is_not_an_endpoint() {
        let samples = vec![
            "2026-09-21 14:00:01 10.0.0.1 10.0.0.2 443 TCP accept",
            "2026-09-21 14:00:02 10.0.0.3 10.0.0.4 444 TCP accept",
            "2026-09-21 14:00:03 10.0.0.5 10.0.0.6 445 TCP accept",
        ];
        let pattern = Onboarder::synthesize_regex(&samples).unwrap();
        let re = Regex::new(&pattern).unwrap();
        let caps = re.captures(samples[0]).unwrap();
        assert_eq!(caps.name("src_ip").map(|m| m.as_str()), Some("10.0.0.1"));
        assert_eq!(caps.name("dst_ip").map(|m| m.as_str()), Some("10.0.0.2"));
        assert_eq!(caps.name("src_port").map(|m| m.as_str()), Some("443"));
        // The synthesized pattern must pass its own validator — the whole point.
        let parser = ParserDefinition {
            vendor: "v".into(),
            device_model: "m".into(),
            regex_pattern: pattern,
            action_mappings: HashMap::new(),
            sample_logs: vec![],
            confidence_score: 1.0,
            created_at: 0,
            schema_version: 0,
            regex_cache: Arc::new(OnceLock::new()),
        };
        let report = Onboarder::validate_parser(&parser, &samples).unwrap();
        assert!(
            report.passed,
            "a synthesized pattern must survive its own validation: {:?}",
            report.errors
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
            schema_version: 0,
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

    /// New definitions stamp [`PARSER_SCHEMA_VERSION`]; files published before
    /// the field existed (no `schema_version` key at all) still load — as
    /// version 0 — instead of failing `from_yaml`'s missing-field rejection.
    #[test]
    fn test_schema_version_roundtrip_and_legacy_default() {
        let parser = ParserDefinition {
            vendor: "v".into(),
            device_model: "m".into(),
            regex_pattern: r"^src=(?P<src_ip>\S+) dst=(?P<dst_ip>\S+)$".to_string(),
            action_mappings: HashMap::new(),
            sample_logs: vec![],
            confidence_score: 1.0,
            created_at: 0,
            schema_version: PARSER_SCHEMA_VERSION,
            regex_cache: Arc::new(OnceLock::new()),
        };
        assert_eq!(PARSER_SCHEMA_VERSION, 1);
        let from_json = ParserDefinition::from_json(&parser.to_json().unwrap()).unwrap();
        assert_eq!(from_json.schema_version, PARSER_SCHEMA_VERSION);
        let from_yaml = ParserDefinition::from_yaml(&parser.to_yaml().unwrap()).unwrap();
        assert_eq!(from_yaml.schema_version, PARSER_SCHEMA_VERSION);

        // A legacy file carries every field EXCEPT schema_version.
        let legacy_yaml = concat!(
            "vendor: \"V\"\n",
            "device_model: \"M\"\n",
            "confidence_score: 1.00\n",
            "created_at: 1700000000000\n",
            "regex_pattern: \"^src=(?P<src_ip>[0-9.]+)$\"\n",
            "action_mappings: {}\n",
            "sample_logs:\n",
            "  - \"src=10.0.0.1\"\n",
        );
        let legacy =
            ParserDefinition::from_yaml(legacy_yaml).expect("legacy file must keep loading");
        assert_eq!(legacy.schema_version, 0, "absent version defaults to 0");
        assert_eq!(legacy.vendor, "V");

        let legacy_json = r#"{"vendor":"V","device_model":"M","regex_pattern":"^x$",
            "action_mappings":{},"sample_logs":[],"confidence_score":1.0,"created_at":0}"#;
        let legacy_j = ParserDefinition::from_json(legacy_json).unwrap();
        assert_eq!(legacy_j.schema_version, 0);
    }

    /// CEF synthesis captures endpoints, CEF-short ports, and the hyphenated
    /// `act=` verb; dispositions come from the CEF vocabulary, not UNKNOWN.
    #[test]
    fn test_cef_synthesizer_captures_endpoints_and_action() {
        let samples = vec![
            "CEF:0|Fortinet|FortiGate|v7.0.2|0000000019|traffic:forward accept|3|src=192.168.1.146 spt=25297 dst=203.0.113.207 dpt=80 proto=6 act=accept",
            "CEF:0|Fortinet|FortiGate|v7.0.2|0000000014|traffic:forward server-rst|3|src=192.168.3.14 spt=46909 dst=198.51.100.3 dpt=993 proto=6 act=server-rst",
            "CEF:0|Fortinet|FortiGate|v7.0.2|0000000012|traffic:forward deny|3|src=192.168.6.68 spt=46825 dst=198.51.100.142 dpt=123 proto=17 act=deny",
        ];
        let pattern = Onboarder::synthesize_regex(&samples).unwrap();
        assert!(
            pattern.contains(r"CEF:(?P<cef_version>\d+)\|"),
            "mandatory header anchor missing: {pattern}"
        );
        let re = Regex::new(&pattern).expect("synthesized CEF regex must compile");
        let caps = re.captures(samples[0]).unwrap();
        assert_eq!(caps.name("src_ip").unwrap().as_str(), "192.168.1.146");
        assert_eq!(caps.name("src_port").unwrap().as_str(), "25297");
        assert_eq!(caps.name("dst_ip").unwrap().as_str(), "203.0.113.207");
        assert_eq!(caps.name("dst_port").unwrap().as_str(), "80");
        assert_eq!(caps.name("action").unwrap().as_str(), "accept");
        let caps2 = re.captures(samples[1]).unwrap();
        assert_eq!(caps2.name("action").unwrap().as_str(), "server-rst");

        let (def, _) = Onboarder::generate_parser("fortinet", "fgt-cef", &samples).unwrap();
        let ev = def.parse(samples[0]).unwrap();
        assert_eq!(ev.src_endpoint.ip.as_deref(), Some("192.168.1.146"));
        assert_eq!(ev.dst_endpoint.port, Some(80));
        assert_eq!(ev.disposition, disposition::ALLOWED);
        let ev_deny = def.parse(samples[2]).unwrap();
        assert_eq!(ev_deny.disposition, disposition::BLOCKED);
        // CEF-session verbs map to ALLOWED (never UNKNOWN), like the native extractor.
        let ev_rst = def.parse(samples[1]).unwrap();
        assert_eq!(ev_rst.disposition, disposition::ALLOWED);
    }

    /// CEF dispatch wins over flow-arrow: an extension block containing `->`
    /// must still synthesize a CEF pattern, not a flow pattern.
    #[test]
    fn test_cef_dispatch_first_despite_arrow_in_extension() {
        let samples = vec![
            "CEF:0|Fortinet|FortiGate|v7.0.2|0000000019|traffic:forward accept|3|src=192.168.1.146 spt=25297 dst=203.0.113.207 dpt=80 proto=6 act=accept msg=a->b",
            "CEF:0|Fortinet|FortiGate|v7.0.2|0000000014|traffic:forward accept|3|src=192.168.3.14 spt=46909 dst=198.51.100.3 dpt=993 proto=6 act=accept msg=c->d",
            "CEF:0|Fortinet|FortiGate|v7.0.2|0000000012|traffic:forward accept|3|src=192.168.6.68 spt=46825 dst=198.51.100.142 dpt=123 proto=17 act=accept msg=e->f",
        ];
        let pattern = Onboarder::synthesize_regex(&samples).unwrap();
        assert!(
            pattern.contains("CEF:"),
            "CEF must win dispatch over `->`: {pattern}"
        );
        let re = Regex::new(&pattern).unwrap();
        assert_eq!(
            re.captures(samples[0])
                .unwrap()
                .name("src_ip")
                .unwrap()
                .as_str(),
            "192.168.1.146"
        );
    }

    /// JSON synthesis over a MIXED-type training set (alert + flow + dns):
    /// the 5-tuple is mandatory, `alert.action` is optional, and all three
    /// shapes validate — under 20 samples the gate is strict (100%).
    #[test]
    fn test_json_synthesizer_mixed_eve_types_validate() {
        let samples = vec![
            r#"{"timestamp": "2026-09-21T14:00:01.3102+0000", "event_type": "alert", "src_ip": "10.0.0.22", "src_port": 56529, "dest_ip": "198.51.100.188", "dest_port": 1521, "proto": "TCP", "alert": {"action": "blocked", "signature_id": 2000419}}"#,
            r#"{"timestamp": "2026-09-21T14:00:03.2768+0000", "event_type": "flow", "src_ip": "10.0.0.98", "src_port": 28488, "dest_ip": "203.0.113.74", "dest_port": 8080, "proto": "TCP"}"#,
            r#"{"timestamp": "2026-09-21T14:00:05.1653+0000", "event_type": "dns", "src_ip": "10.0.0.83", "src_port": 39958, "dest_ip": "9.9.9.9", "dest_port": 53, "proto": "UDP"}"#,
        ];
        let pattern = Onboarder::synthesize_regex(&samples).unwrap();
        assert!(
            pattern.starts_with(r"^\s*\{"),
            "JSON pattern must anchor at object start: {pattern}"
        );
        let (def, report) = Onboarder::generate_parser("suricata", "eve", &samples).unwrap();
        assert!(
            report.passed,
            "mixed EVE types must validate: {:?}",
            report.errors
        );

        let ev_alert = def.parse(samples[0]).unwrap();
        assert_eq!(ev_alert.src_endpoint.ip.as_deref(), Some("10.0.0.22"));
        assert_eq!(ev_alert.src_endpoint.port, Some(56529));
        assert_eq!(ev_alert.dst_endpoint.ip.as_deref(), Some("198.51.100.188"));
        assert_eq!(ev_alert.dst_endpoint.port, Some(1521));
        assert_eq!(ev_alert.disposition, disposition::BLOCKED);

        // The flow record has no `alert.action` — it still parses, with an
        // UNKNOWN disposition rather than a match failure.
        let ev_flow = def.parse(samples[1]).unwrap();
        assert_eq!(ev_flow.src_endpoint.ip.as_deref(), Some("10.0.0.98"));
        assert_eq!(ev_flow.dst_endpoint.port, Some(8080));
    }
}
