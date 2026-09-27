use std::time::Instant;
use ulpf_ai::{
    AlertSeverity, AnomalyType, DrainConfig, DrainMiner, DynamicParserRegistry, Onboarder,
};
use ulpf_core::schema::ocsf::{activity_id, disposition, CLASS_UID_NETWORK_ACTIVITY};

// ============================================================================
// 1. DRAIN3 TEMPLATE EXTRACTION & CLUSTERING TESTS
// ============================================================================

#[test]
fn test_drain_template_clustering_cisco_asa() {
    let mut miner = DrainMiner::new(DrainConfig::default());

    let log1 = "%ASA-6-302013: Built outbound TCP connection 1000672 for outside:203.0.113.54/25 (203.0.113.54/25) to inside:10.1.6.180/52369 (198.51.100.209/52369)";
    let log2 = "%ASA-6-302013: Built outbound TCP connection 1000673 for outside:198.51.100.12/80 (198.51.100.12/80) to inside:10.2.4.99/44123 (198.51.100.210/44123)";
    let log3 = "%ASA-6-302013: Built outbound TCP connection 1000674 for outside:192.0.2.1/443 (192.0.2.1/443) to inside:10.3.1.20/33120 (198.51.100.211/33120)";

    let res1 = miner.add_log(log1);
    assert_eq!(res1.cluster_id, 1);
    assert!(
        res1.anomaly.is_some(),
        "First occurrence should trigger NewTemplate alert"
    );
    assert_eq!(res1.anomaly.unwrap().anomaly_type, AnomalyType::NewTemplate);

    let res2 = miner.add_log(log2);
    assert_eq!(
        res2.cluster_id, 1,
        "Log 2 should match existing Cisco ASA template"
    );
    assert!(
        res2.anomaly.is_none(),
        "Matched template should not trigger alert"
    );

    let res3 = miner.add_log(log3);
    assert_eq!(
        res3.cluster_id, 1,
        "Log 3 should match existing Cisco ASA template"
    );

    let cluster = miner.get_cluster(1).expect("Cluster 1 must exist");
    assert_eq!(cluster.count, 3);
    assert!(
        cluster.template.contains("<*>"),
        "Template should contain wildcard token"
    );
}

#[test]
fn test_drain_template_clustering_fortinet() {
    let mut miner = DrainMiner::new(DrainConfig::default());

    let log1 = r#"date=2026-09-21 time=14:00:02 devname="FGT-DC-EDGE" devid="FGT60D4614041123" logid="0000000019" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.7.45 srcport=29853 dstip=203.0.113.46 dstport=53 proto=17 action="timeout""#;
    let log2 = r#"date=2026-09-21 time=14:00:05 devname="FGT-CORP-FW01" devid="FGT100E391780045" logid="0000000003" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.5.14 srcport=50470 dstip=198.51.100.22 dstport=3389 proto=6 action="accept""#;

    let res1 = miner.add_log(log1);
    assert!(res1.is_new);
    assert!(
        res1.template.contains("<*>"),
        "Fortinet template must contain masked tokens: {}",
        res1.template
    );

    let res2 = miner.add_log(log2);
    assert!(res2.template.contains("<*>"));
}

#[test]
fn test_drain_template_clustering_palo_alto() {
    let mut miner = DrainMiner::new(DrainConfig::default());

    let log1 = "1,2026/09/21 14:00:01,001801000001,TRAFFIC,deny,2304,2026/09/21 14:00:00,192.168.1.19,203.0.113.87,198.51.100.32,203.0.113.87,Trust_to_Untrust,acme\\agarcia,,ping,vsys1,DMZ,WAN,ethernet1/1,ethernet1/2,default,,100412,1,0,0,0,0,0x400000,icmp,drop,4983547,454039,4529508,9510,2026/09/21 13:56:28,213,web-hosting,0,100000129,0x0";
    let log2 = "1,2026/09/21 14:00:04,001801000003,TRAFFIC,drop,2304,2026/09/21 14:00:04,192.168.1.19,198.51.100.128,198.51.100.30,198.51.100.128,Trust_to_Untrust,acme\\dchen,,ntp,vsys1,Trust,Untrust,ethernet1/1,ethernet1/2,default,,100674,1,37269,123,37269,123,0x400000,udp,drop,3271827,863823,2408004,5870,2026/09/21 13:54:12,352,content-delivery-networks,0,100002795,0x0";

    let res1 = miner.add_log(log1);
    assert!(res1.is_new);
    assert!(
        res1.template.contains("<*>"),
        "Palo Alto template must mask dynamic fields: {}",
        res1.template
    );

    let res2 = miner.add_log(log2);
    assert!(res2.template.contains("<*>"));
}

// ============================================================================
// 2. ANOMALY DETECTION TESTS
// ============================================================================

#[test]
fn test_drain_anomaly_detection_unknown_template() {
    let mut miner = DrainMiner::new(DrainConfig::default());

    // Ingest standard logs
    miner.add_log("%ASA-6-302013: Built outbound TCP connection 1001 for outside:1.1.1.1/80 to inside:2.2.2.2/1000");
    miner.add_log("%ASA-6-302013: Built outbound TCP connection 1002 for outside:1.1.1.2/80 to inside:2.2.2.3/1001");

    // Ingest radically different structural log (e.g. unknown proprietary alert)
    let attack_log = "ALERT_MALICIOUS_BUFFER_OVERFLOW: exploit attempt detected from 45.33.32.156 target_port=445 payload_size=1024";
    let res = miner.add_log(attack_log);

    assert_eq!(
        res.cluster_id, 2,
        "Novel structural log must create a new cluster"
    );
    assert!(res.anomaly.is_some(), "Must generate anomaly alert");
    let alert = res.anomaly.unwrap();
    assert_eq!(alert.anomaly_type, AnomalyType::NewTemplate);
    assert_eq!(alert.severity, AlertSeverity::Medium);
}

#[test]
fn test_drain_rare_cluster_surge() {
    let config = DrainConfig {
        rare_count_threshold: 3,
        surge_multiplier: 1.0,
        ..Default::default()
    };
    let mut miner = DrainMiner::new(config);

    // Establish baseline cluster
    for i in 0..20 {
        miner.add_log(&format!("SYSTEM_HEARTBEAT: status=OK node=worker-{}", i));
    }

    // Create a rare anomaly cluster
    let rare_log = "SECURITY_ALERT: Unauthorized privilege escalation detected by user admin";
    let res_rare1 = miner.add_log(rare_log);
    assert!(res_rare1.is_new);

    // Blast the rare cluster with a sudden surge in traffic
    let mut surge_alert_triggered = false;
    for _ in 0..10 {
        let res = miner.add_log(rare_log);
        if let Some(ref alert) = res.anomaly {
            if alert.anomaly_type == AnomalyType::RareClusterSurge {
                surge_alert_triggered = true;
                assert_eq!(alert.severity, AlertSeverity::High);
                break;
            }
        }
    }

    assert!(
        surge_alert_triggered,
        "Surging traffic on a previously rare cluster must trigger RareClusterSurge alert"
    );
}

// ============================================================================
// 3. 1-CLICK AIR-GAPPED ONBOARDING TESTS
// ============================================================================

#[test]
fn test_onboarder_synthesize_juniper_srx() {
    let samples = vec![
        "RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.168.10.55/49152->10.0.0.1/443 None None 6 sample-policy trust untrust 12345 N/A(N/A) ge-0/0/0.0",
        "RT_FLOW: RT_FLOW_SESSION_CREATE: session created 10.200.1.4/51234->198.51.100.25/80 None None 6 web-out trust untrust 12347 N/A(N/A) ge-0/0/0.0",
        "RT_FLOW: RT_FLOW_SESSION_CREATE: session created 172.16.5.20/38112->203.0.113.88/8080 None None 6 app-out trust dmz 12349 N/A(N/A) ge-0/0/1.0",
    ];

    let (parser_def, report) = Onboarder::generate_parser("juniper_srx", "srx-300", &samples)
        .expect("Synthesis must succeed");

    assert!(
        report.passed,
        "Synthesized parser must pass 100% validation: {:?}",
        report.errors
    );
    assert_eq!(report.total_samples, 3);
    assert_eq!(report.matched_samples, 3);

    // Test parsing a 4th unseen sample using the generated parser
    let test_log = "RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.168.99.100/60000->8.8.8.8/53 None None 17 dns-out trust untrust 99999 N/A(N/A) ge-0/0/0.0";
    let event = parser_def.parse(test_log).expect("Must parse test log");

    assert_eq!(event.class_uid, CLASS_UID_NETWORK_ACTIVITY);
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("192.168.99.100"));
    assert_eq!(event.src_endpoint.port, Some(60000));
    assert_eq!(event.dst_endpoint.ip.as_deref(), Some("8.8.8.8"));
    assert_eq!(event.dst_endpoint.port, Some(53));
    assert_eq!(event.metadata.product.vendor_name, "juniper_srx");
    assert_eq!(event.activity_id, activity_id::OPEN);
    assert_eq!(event.disposition, disposition::ALLOWED);
}

#[test]
fn test_onboarder_checkpoint_format() {
    let samples = vec![
        "2026-09-21 14:00:01 CheckPoint-FW drop 192.168.10.15:52341 -> 10.0.0.25:443 proto TCP rule 101",
        "2026-09-21 14:00:02 CheckPoint-FW accept 192.168.10.16:52342 -> 10.0.0.25:80 proto TCP rule 102",
        "2026-09-21 14:00:03 CheckPoint-FW drop 192.168.10.17:52343 -> 10.0.0.26:53 proto UDP rule 103",
    ];

    let (parser_def, report) = Onboarder::generate_parser("CheckPoint", "Quantum", &samples)
        .expect("Failed to generate CheckPoint parser");

    assert!(
        report.passed,
        "Sandbox validation passed: {:?}",
        report.errors
    );
    assert_eq!(report.matched_samples, 3);

    let event1 = parser_def.parse(samples[0]).unwrap();
    assert_eq!(event1.src_endpoint.ip.as_deref(), Some("192.168.10.15"));
    assert_eq!(event1.src_endpoint.port, Some(52341));
    assert_eq!(event1.dst_endpoint.ip.as_deref(), Some("10.0.0.25"));
    assert_eq!(event1.dst_endpoint.port, Some(443));
    assert_eq!(event1.disposition, disposition::DROPPED);
    assert_eq!(event1.connection_info.protocol_name.as_deref(), Some("TCP"));

    let event2 = parser_def.parse(samples[1]).unwrap();
    assert_eq!(event2.disposition, disposition::ALLOWED);
    assert_eq!(event2.src_endpoint.ip.as_deref(), Some("192.168.10.16"));
}

#[test]
fn test_dynamic_parser_registry() {
    let mut registry = DynamicParserRegistry::new();

    let samples = vec![
        "FIREWALL_EVENT: pass proto=TCP src=192.168.1.10 srcport=44300 dst=10.0.0.5 dstport=80 action=allow",
        "FIREWALL_EVENT: pass proto=UDP src=192.168.1.15 srcport=53000 dst=8.8.8.8 dstport=53 action=allow",
        "FIREWALL_EVENT: pass proto=TCP src=192.168.1.20 srcport=44301 dst=10.0.0.6 dstport=80 action=allow",
    ];

    let (parser_def, report) =
        Onboarder::generate_parser("custom_waf", "waf-v1", &samples).expect("Synthesis");
    assert!(report.passed);
    let key = registry.register(parser_def);
    assert_eq!(key, "custom_waf:waf-v1", "composite vendor:model key");

    assert_eq!(registry.len(), 1);

    let test_log = "FIREWALL_EVENT: pass proto=TCP src=172.16.0.1 srcport=33000 dst=192.168.1.1 dstport=22 action=allow";
    let parsed = registry
        .parse("custom_waf", test_log)
        .expect("Parse with custom_waf");
    assert_eq!(parsed.src_endpoint.ip.as_deref(), Some("172.16.0.1"));
    assert_eq!(parsed.src_endpoint.port, Some(33000));
    assert_eq!(parsed.dst_endpoint.ip.as_deref(), Some("192.168.1.1"));
    assert_eq!(parsed.dst_endpoint.port, Some(22));
}

// ============================================================================
// 4. MICROSECOND CPU PERFORMANCE VALIDATION
// ============================================================================

#[test]
fn test_drain_microsecond_performance() {
    let mut miner = DrainMiner::new(DrainConfig::default());
    let log = "%ASA-6-302013: Built outbound TCP connection 1000672 for outside:203.0.113.54/25 to inside:10.1.6.180/52369";

    // Warm-up
    miner.add_log(log);

    let iterations = 1000;
    let start = Instant::now();
    for _ in 0..iterations {
        let res = miner.add_log(log);
        assert!(!res.is_new);
    }
    let total_micros = start.elapsed().as_micros();
    let avg_micros = (total_micros as f64) / (iterations as f64);

    #[cfg(debug_assertions)]
    let max_allowed_micros = 300.0; // Debug builds without compiler optimizations and under parallel thread contention
    #[cfg(not(debug_assertions))]
    let max_allowed_micros = 25.0; // Release optimized build

    assert!(
        avg_micros < max_allowed_micros,
        "Drain3 log template mining should take < {:.0} µs on CPU, took {:.2} µs",
        max_allowed_micros,
        avg_micros
    );
}

#[test]
fn test_drain_unique_event_patterns_anchor_tokens() {
    let mut miner = DrainMiner::new(DrainConfig::default());

    // Two firewall logs with identical length and structure, differing only in action: ALLOW vs DENY
    let log_allow =
        "FIREWALL connection 1001 protocol TCP action ALLOW src 192.168.1.10 dst 10.0.0.1";
    let log_deny =
        "FIREWALL connection 1002 protocol TCP action DENY src 192.168.1.10 dst 10.0.0.1";

    let res1 = miner.add_log(log_allow);
    assert_eq!(res1.cluster_id, 1);
    assert!(res1.is_new);

    let res2 = miner.add_log(log_deny);
    // In vanilla Drain without anchor tokens, 8 out of 9 tokens match (88% similarity > 50% threshold),
    // which would improperly merge them into "FIREWALL connection <*> protocol TCP action <*> src <*> dst <*>".
    // With DrainDotNet's UniqueEventPatterns anchor tokens, ALLOW != DENY forces similarity to 0.0,
    // creating a distinct cluster!
    assert_eq!(
        res2.cluster_id, 2,
        "Anchor tokens (ALLOW vs DENY) must NEVER be merged into a single cluster"
    );
    assert!(res2.is_new);

    let cluster1 = miner.get_cluster(1).unwrap();
    let cluster2 = miner.get_cluster(2).unwrap();

    assert!(cluster1.template.contains("ALLOW"));
    assert!(cluster2.template.contains("DENY"));

    // ------------------------------------------------------------------
    // P6.1: kv-format anchors — enforcement must see the VALUE of
    // `key="value"` tokens (real FortiGate corpus line + a single-field
    // mutation to deny; every other kv key, including `time=`, differs at
    // most cosmetically after masking, so without value-aware anchors the
    // two lines sit far above the 0.5 similarity threshold).
    // ------------------------------------------------------------------
    let mut kv_miner = DrainMiner::new(DrainConfig::default());
    let fgt_accept = r#"<189>date=2026-09-21 time=14:00:05 devname="FGT-CORP-FW01" devid="FGT100E391780045" eventtime=1789979405000057304 tz="+0000" logid="0000000003" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.5.14 srcport=50470 srcintf="trust" srcintfrole="lan" dstip=198.51.100.22 dstport=3389 dstintf="untrust" dstintfrole="wan" poluuid="d607b1e9-4148-51ec-8962-e61e05d05051" sessionid=1000230 proto=6 action="accept" policyid=41 policytype="policy" service="RDP" trandisp="snat" transip=198.51.100.27 transport=50470 duration=1120 sentbyte=410932 rcvdbyte=1889872 sentpkt=386 rcvdpkt=3586 appcat="unscanned""#;
    let fgt_deny = fgt_accept
        .replace("time=14:00:05", "time=14:00:06")
        .replace("action=\"accept\"", "action=\"deny\"");
    let fgt_accept_2 = fgt_accept
        .replace("time=14:00:05", "time=14:00:09")
        .replace("srcip=192.168.5.14", "srcip=192.168.7.45");

    let kv_a = kv_miner.add_log(fgt_accept);
    let kv_d = kv_miner.add_log(&fgt_deny);
    let kv_a2 = kv_miner.add_log(&fgt_accept_2);

    assert_eq!(
        kv_a.cluster_id, kv_a2.cluster_id,
        "identical kv action must cluster together (no over-split)"
    );
    assert_ne!(
        kv_a.cluster_id, kv_d.cluster_id,
        "kv action values (accept vs deny) are anchors: Action Inviolability \
         must hold through key=\"value\" tokens"
    );
    let kv_cluster = kv_miner.get_cluster(kv_a.cluster_id).unwrap();
    assert!(
        kv_cluster.template.contains("action=\"accept"),
        "winning kv action value stays literal in the template"
    );
}

// ============================================================================
// P6.1 — DYNAMIC SYSLOG MESSAGE-CODE ANCHORS
// ============================================================================
// The masker preserves `%FAC-SEV-CODE:` tags verbatim, but a tag is only
// 1 token of ~14 — cross-code lines sit at sim 0.79 (or ratchet to 1.0 after
// early generalization) and merged 302013/302014/302015/106001 into shared
// clusters, destroying GA (mixed GT tags) and TA (tag position generalized
// to `<*>`, failing the verbatim-GT-tag clause). The tag must act as a
// per-line anchor: clusters are tag-homogeneous.
#[test]
fn test_drain_syslog_message_code_anchors() {
    use ulpf_ai::drain::syslog_tag_of;

    // helper contract: tag extraction mirrors the masker's protection pattern
    let asa_302013 = "<166>Sep 21 14:00:43 asa-edge-01 %ASA-6-302013: Built inbound TCP connection 1001322 for outside:203.0.113.137/993 (203.0.113.137/993) to inside:10.1.18.77/26375 (198.51.100.238/26375)";
    assert_eq!(syslog_tag_of(asa_302013).as_deref(), Some("%ASA-6-302013:"));
    assert_eq!(
        syslog_tag_of(r#"date=2026-09-21 devname="FGT-DC-EDGE" type="traffic""#),
        None,
        "untagged vendor formats carry no message-code anchor"
    );

    let mut miner = DrainMiner::new(DrainConfig::default());

    // --- (1) same code, near-identical shape: must NOT over-split ---------
    let r1 = asa_302013;
    let r2 = "<166>Sep 21 14:00:58 asa-vpn-gw01 %ASA-6-302013: Built outbound TCP connection 1000734 for outside:198.51.100.50/1433 (198.51.100.50/1433) to inside:10.1.18.77/16288 (198.51.100.227/16288)";
    let res1 = miner.add_log(r1);
    let res2 = miner.add_log(r2);
    assert_eq!(
        res1.cluster_id, res2.cluster_id,
        "same message code must stay one cluster (no over-split)"
    );

    // --- (2) 302013 vs 302015, direct high-sim pair (11/14 = 0.79) --------
    let r5 = "<166>Sep 21 14:00:04 asa-core-fw %ASA-6-302015: Built inbound UDP connection 1000556 for outside:198.51.100.18/5060 (198.51.100.18/5060) to inside:10.1.6.180/59770 (198.51.100.207/59770)";
    let res5 = miner.add_log(r5);
    assert_ne!(
        res1.cluster_id, res5.cluster_id,
        "302013 and 302015 are distinct message codes: never one cluster"
    );

    // --- (3) the observed corpus ratchet: 302014 generalizes (host,
    // duration, teardown-verb tail), then 106001 lands at sim >= 0.5 and
    // drags the TAG position to `<*>`. Tag anchoring must cut it off.
    let t1 = "<166>Sep 21 14:01:13 asa-dc-01 %ASA-6-302014: Teardown TCP connection 1001269 for outside:203.0.113.54/123 to inside:10.1.14.89/54772 duration 0:21:02 bytes 967806 Reset-I";
    let t2 = "<166>Sep 21 14:00:02 asa-core-fw %ASA-6-302014: Teardown TCP connection 1000780 for outside:203.0.113.163/3306 to inside:10.1.9.41/27459 duration 0:27:58 bytes 3350664 Reset-I";
    let t3 = "<166>Sep 21 14:00:30 asa-core-fw %ASA-6-302014: Teardown TCP connection 1000805 for outside:198.51.100.59/22 to inside:10.1.1.196/37888 duration 0:29:16 bytes 632624 Reset-O";
    let teardown_seed = miner.add_log(t1);
    let res_t2 = miner.add_log(t2);
    let res_t3 = miner.add_log(t3);
    assert_eq!(teardown_seed.cluster_id, res_t2.cluster_id);
    assert_eq!(teardown_seed.cluster_id, res_t3.cluster_id);

    let r4 = "<162>Sep 21 14:00:10 asa-vpn-gw01 %ASA-2-106001: Inbound TCP connection denied from 203.0.113.143/27501 to 10.1.9.208/110 flags RST on interface outside";
    let res4 = miner.add_log(r4);
    assert_ne!(
        teardown_seed.cluster_id, res4.cluster_id,
        "106001 must never join a 302014 cluster (observed corpus merge)"
    );

    // --- (4) TA contract: every cluster template carries ITS OWN tag -----
    //      verbatim — the verbatim-GT-tag clause of template_is_valid.
    let c_302013 = miner.get_cluster(res1.cluster_id).unwrap();
    let c_302015 = miner.get_cluster(res5.cluster_id).unwrap();
    let c_302014 = miner.get_cluster(teardown_seed.cluster_id).unwrap();
    let c_106001 = miner.get_cluster(res4.cluster_id).unwrap();
    assert!(c_302013.template.contains("%ASA-6-302013:"));
    assert!(c_302015.template.contains("%ASA-6-302015:"));
    assert!(c_302014.template.contains("%ASA-6-302014:"));
    assert!(c_106001.template.contains("%ASA-2-106001:"));
}

#[test]
fn test_evaluator_comparative_run() {
    use ulpf_ai::EvaluatorEngine;

    let sample_corpus = vec![
        "%ASA-6-302013: Built inbound UDP connection 1001 for outside:1.1.1.1/53 to inside:2.2.2.2/53".to_string(),
        "%ASA-6-302013: Built inbound UDP connection 1002 for outside:1.1.1.2/53 to inside:2.2.2.3/53".to_string(),
        r#"date=2026-09-21 time=14:00:02 devname="FGT-DC-EDGE" type="traffic" srcip=10.0.0.1"#.to_string(),
        "1,2026/09/21 14:00:01,001801000001,TRAFFIC,deny,2304,2026/09/21 14:00:00,192.168.1.19,203.0.113.87,198.51.100.32,203.0.113.87,Trust_to_Untrust,acme\\agarcia,,ping,vsys1,DMZ,WAN,ethernet1/1,ethernet1/2,default,,100412,1,0,0,0,0,0x400000,icmp,drop,4983547,454039,4529508,9510,2026/09/21 13:56:28,213,web-hosting,0,100000129,0x0".to_string(),
    ];

    let report = EvaluatorEngine::evaluate(&sample_corpus, 1, 2);

    let baseline = report
        .baseline
        .as_ref()
        .expect("Baseline result should be present");
    assert!(baseline.throughput.events_per_sec > 0.0);
    assert!(baseline.accuracy.lossless_sha256_match_pct >= 99.0);
    assert!(baseline.accuracy.vendor_classification_accuracy_pct >= 95.0);

    let tiered = report
        .tiered_pipeline
        .as_ref()
        .expect("Tiered result should be present");
    assert!(tiered.throughput.events_per_sec > 0.0);
    assert!(tiered.accuracy.action_inviolability_pct >= 100.0);
    assert!(tiered.accuracy.grouping_accuracy_ga_pct >= 75.0);
    assert!(tiered.latency.p50_micros > 0.0);

    let md = report.to_markdown();
    assert!(md.contains("ULPF Hardcore Architectural"));
    // The five-field mean is not an F1 — the retired "Macro F1" label must
    // never resurface in generated output.
    assert!(
        md.contains("Field Extraction Mean Accuracy"),
        "markdown must use the honest name:\n{md}"
    );
    assert!(
        !md.contains("Macro F1"),
        "retired misnomer leaked into markdown"
    );

    let terminal_dash = report.render_terminal_dashboard();
    assert!(terminal_dash.contains("ULPF HARDCORE ARCHITECTURAL & ACCURACY EVALUATOR"));
}

// ============================================================================
// P1 — EVALUATOR GROUND-TRUTH / RULER TESTS (measurement-first fixes)
// ============================================================================

use ulpf_ai::drain::mask_line;
use ulpf_ai::EvaluatorEngine;

/// OCSF disposition alignment: deny is Blocked (disposition_id 2), never Dropped;
/// session-end states of permitted traffic are Allowed.
#[test]
fn test_gt_disposition_ocfs_alignment() {
    // ASA deny-by-policy -> Blocked
    let asa_deny = "<164>Sep 21 14:00:00 fw %ASA-4-106023: Deny tcp src outside:198.51.100.5/1234 dst inside:10.0.0.2/80 access-group out";
    let (_, _, act) = EvaluatorEngine::extract_ground_truth(asa_deny);
    assert_eq!(act.as_deref(), Some("Blocked"));

    // ASA built -> Allowed
    let asa_built = "<162>Sep 21 14:00:00 fw %ASA-6-302013: Built outbound TCP connection 1 for outside:10.0.0.1/1000 to inside:10.0.0.2/80";
    let (_, _, act) = EvaluatorEngine::extract_ground_truth(asa_built);
    assert_eq!(act.as_deref(), Some("Allowed"));

    // FortiGate deny -> Blocked
    let fgt_deny = r#"<189>date=2026-09-21 time=14:00:02 devname="FGT" logid="0000000019" type="traffic" action="deny" srcip=10.0.0.1 dstip=203.0.113.1 proto=6"#;
    let (v, t, act) = EvaluatorEngine::extract_ground_truth(fgt_deny);
    assert_eq!(v, "Fortinet");
    assert_eq!(t, "fortigate_traffic");
    assert_eq!(act.as_deref(), Some("Blocked"));

    // FortiGate session-end (timeout/close/rst) -> Allowed, not Unknown
    for action in ["timeout", "close", "client-rst", "server-rst"] {
        let raw = format!(
            r#"<189>date=2026-09-21 time=14:00:02 devname="FGT" logid="0000000019" type="traffic" action="{action}" srcip=10.0.0.1 dstip=203.0.113.1 proto=6"#
        );
        let (_, _, act) = EvaluatorEngine::extract_ground_truth(&raw);
        assert_eq!(act.as_deref(), Some("Allowed"), "action={action}");
    }
}

/// CEF ground truth: vendor comes from Header Field 2 (any vendor's CEF),
/// disposition from the `act=` extension token.
#[test]
fn test_gt_cef_vendor_and_action() {
    let cef_accept = "CEF:0|Fortinet|FortiGate|v7.0.2|0000000019|traffic:forward accept|3|deviceExternalId=FGT1 src=192.168.1.1 spt=25297 dst=203.0.113.1 dpt=80 proto=6 act=accept";
    let (v, t, act) = EvaluatorEngine::extract_ground_truth(cef_accept);
    assert_eq!(v, "Fortinet");
    assert_eq!(t, "cef");
    assert_eq!(act.as_deref(), Some("Allowed"));

    let cef_deny = "CEF:0|Cisco|ASA|v9.16|4-106023|Deny|2|src=192.0.2.1 spt=443 dst=10.0.0.1 dpt=22 proto=6 act=deny";
    let (v, _, act) = EvaluatorEngine::extract_ground_truth(cef_deny);
    assert_eq!(v, "Cisco");
    assert_eq!(act.as_deref(), Some("Blocked"));

    let cef_timeout =
        "CEF:0|Fortinet|FortiGate|v7.0.2|0000000019|traffic|3|act=timeout src=10.0.0.1";
    let (_, _, act) = EvaluatorEngine::extract_ground_truth(cef_timeout);
    assert_eq!(act.as_deref(), Some("Allowed"));
}

/// Explicit vendor label map — fixed table, never fuzzy matching.
#[test]
fn test_audit_vendor_label_map() {
    assert_eq!(EvaluatorEngine::map_audit_vendor("oisf"), "suricata");
    assert_eq!(EvaluatorEngine::map_audit_vendor("netgate"), "pfsense");
    assert_eq!(EvaluatorEngine::map_audit_vendor("cisco"), "cisco");
    assert_eq!(EvaluatorEngine::map_audit_vendor("unknown"), "unknown");
}

/// Suricata EVE ground truth: an explicit event-level `action` is authoritative;
/// without one, alert = Blocked (detection), dns/flow = Allowed.
#[test]
fn test_gt_suricata_eve_action() {
    let alert_allowed = r#"{"timestamp": "2026-09-21T14:00:06.4554+0000", "event_type": "alert", "src_ip": "10.0.0.8", "alert": {"action": "allowed", "signature": "ET SCAN", "severity": 3}}"#;
    let (_, tag, act) = EvaluatorEngine::extract_ground_truth(alert_allowed);
    assert_eq!(tag, "suricata_alert");
    assert_eq!(act.as_deref(), Some("Allowed"), "explicit allowed must win");

    let alert_blocked = r#"{"timestamp": "2026-09-21T14:00:06.4554+0000", "event_type": "alert", "src_ip": "10.0.0.8", "alert": {"action": "blocked", "signature": "ET SCAN", "severity": 2}}"#;
    let (_, _, act) = EvaluatorEngine::extract_ground_truth(alert_blocked);
    assert_eq!(act.as_deref(), Some("Blocked"));

    let alert_no_action = r#"{"timestamp": "2026-09-21T14:00:06.4554+0000", "event_type": "alert", "src_ip": "10.0.0.8", "alert": {"signature": "ET SCAN", "severity": 2}}"#;
    let (_, _, act) = EvaluatorEngine::extract_ground_truth(alert_no_action);
    assert_eq!(act.as_deref(), Some("Blocked"));

    let dns = r#"{"timestamp": "2026-09-21T14:00:05.1653+0000", "event_type": "dns", "src_ip": "10.0.0.83", "dns": {"type": "query"}}"#;
    let (_, tag, act) = EvaluatorEngine::extract_ground_truth(dns);
    assert_eq!(tag, "suricata_flow");
    assert_eq!(act.as_deref(), Some("Allowed"));
}

/// Numeric IANA protocol equivalence: `proto=17` in raw validates an extracted UDP.
#[test]
fn test_protocol_numeric_equivalence_audit() {
    assert!(EvaluatorEngine::raw_contains_numeric(
        "date=2026-01-01 proto=17 spt=5",
        17
    ));
    assert!(EvaluatorEngine::raw_contains_numeric(r#"{"proto": 6}"#, 6));
    assert!(EvaluatorEngine::raw_contains_numeric("...,4,17,...", 17));
    // Must not match on unrelated content
    assert!(!EvaluatorEngine::raw_contains_numeric(
        "proto=TCP spt=443",
        17
    ));
    assert!(!EvaluatorEngine::raw_contains_numeric("proto=17", 6));
}

/// Template validity (honest TA): token-aligned generalization of the masked line,
/// syslog GT tag preserved. No `|| !template.is_empty()` escape hatch remains.
#[test]
fn test_template_validity_alignment() {
    let raw = "%ASA-6-302013: Built outbound TCP connection 1000672 for outside:203.0.113.54/25 (203.0.113.54/25) to inside:10.1.6.180/52369 (198.51.100.209/52369)";
    let masked = mask_line(raw);

    // A template equal to (or a wildcard-generalization of) the masked line is valid
    assert!(EvaluatorEngine::template_is_valid(
        raw,
        &masked,
        "%ASA-6-302013"
    ));

    // Wildcards at masked positions remain valid
    let generalized = masked.replace("203.0.113.54/25", "<*>");
    assert!(EvaluatorEngine::template_is_valid(
        raw,
        &generalized,
        "%ASA-6-302013"
    ));

    // A divergent literal (Built -> Teardown) must FAIL — old metric passed this
    let bogus = masked.replace("Built", "Teardown");
    assert!(!EvaluatorEngine::template_is_valid(
        raw,
        &bogus,
        "%ASA-6-302013"
    ));

    // A template that lost the syslog tag must FAIL
    let tagless = masked.replace("%ASA-6-302013:", "");
    assert!(!EvaluatorEngine::template_is_valid(
        raw,
        &tagless,
        "%ASA-6-302013"
    ));

    // Empty template must FAIL (old metric's `!is_empty()` clause is gone)
    assert!(!EvaluatorEngine::template_is_valid(
        raw,
        "",
        "%ASA-6-302013"
    ));
}

/// Tier-3 must actually onboard a novel cluster: budgeted exemplar dispatch
/// (>= 3 per cluster) + worker-side accumulator. The old single-exemplar rule
/// starved `generate_parser` (which requires >= 3 samples), so onboarded == 0.
#[test]
fn test_tier3_onboards_novel_cluster_with_three_exemplars() {
    use ulpf_ai::pipeline::TieredPipeline;

    let pipeline = TieredPipeline::new();
    let lines = [
        r#"date=2026-09-21 time=14:00:02 devname="NOVEL-FW" type="traffic" subtype="forward" vd="root" srcip=10.11.1.1 srcport=1111 dstip=10.22.2.2 dstport=8443 proto=6 action="allow""#,
        r#"date=2026-09-21 time=14:00:03 devname="NOVEL-FW" type="traffic" subtype="forward" vd="root" srcip=10.11.1.2 srcport=2222 dstip=10.22.2.3 dstport=8444 proto=6 action="allow""#,
        r#"date=2026-09-21 time=14:00:04 devname="NOVEL-FW" type="traffic" subtype="forward" vd="root" srcip=10.11.1.3 srcport=3333 dstip=10.22.2.4 dstport=8445 proto=6 action="allow""#,
    ];
    for line in lines {
        let _ = pipeline.process(line);
    }
    // Out-of-band worker drains the bounded channel asynchronously
    std::thread::sleep(std::time::Duration::from_millis(500));

    let stats = pipeline.stats();
    assert!(
        stats.tier3_laya_onboarded >= 1,
        "novel cluster must onboard with >=3 exemplars (dispatched={}, onboarded={})",
        stats.tier3_laya_dispatches,
        stats.tier3_laya_onboarded
    );
    assert!(
        stats.laya_action_flags > 0,
        "classify_action head must be wired into triage outcome flags"
    );
}

/// Tier-3 maps stay bounded under a flood of distinct novel shapes: the
/// hot-path dispatch table and the worker exemplar buffers both evict oldest
/// past 10k entries instead of growing without limit.
#[test]
fn test_tier3_maps_evict_oldest_past_cap() {
    use ulpf_ai::pipeline::TieredPipeline;

    // Oversized ring buffer so no exemplar is channel-dropped: every distinct
    // shape must reach the worker, otherwise the buffer bound is untestable.
    let pipeline = TieredPipeline::with_ring_buffer_capacity(1 << 15);
    // 10_500 shapes against the 10_000 cap on both maps. The Cisco
    // structural cues (`Built connection outside: inside:`) clear the
    // worker's 0.85 confidence gate into a buffer; only the second token
    // varies, so the signature hash (first-3-tokens fallback) is distinct
    // per shape while Drain still sees one cluster (no syslog tag to split
    // on — a per-line tag would make Drain itself go quadratic).
    for i in 0..10_500 {
        let line = format!("evictprobe w{i:05}x Built connection outside: inside:");
        let _ = pipeline.process(&line);
    }
    assert!(
        pipeline.triage_table_len() <= 10_000,
        "dispatch table must stay capped, len={}",
        pipeline.triage_table_len()
    );
    assert!(
        pipeline.stats().triage_evictions > 0,
        "flooding 10_500 distinct shapes past the 10k cap must evict"
    );
    // The worker drains asynchronously — poll for its buffer evictions.
    let mut evicted = 0;
    for _ in 0..100 {
        evicted = pipeline.stats().cluster_evictions;
        if evicted > 0 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        evicted > 0,
        "worker exemplar buffers must evict oldest past the 10k cap"
    );
}

/// Laya fingerprint priors dominate structural priors: a line carrying another
/// vendor's structural cues still classifies to the fingerprinted vendor.
#[test]
fn test_laya_fingerprint_dominates_structural_priors() {
    use ulpf_ai::LayaDecisionEngine;

    let engine = LayaDecisionEngine::new();
    // `%ASA-` is a Cisco fingerprint; `session`/`Trust` are juniper/paloalto structural cues
    let line = "%ASA-6-302013: Built outbound TCP connection 100 for outside:10.0.0.1/22 Trust session ge-0/0/0";
    let choice = engine.classify_vendor(line);
    assert_eq!(choice.label, "cisco_asa");
    assert!(
        choice.probability > 0.85,
        "fingerprint hit must clear the gating threshold, got {}",
        choice.probability
    );
}

// ============================================================================
// P3: HOT-PATH WIRING (POISONING-SAFE) — pinned order, routes, differential
// ============================================================================

/// Pinned order on Tier-1 miss: native extractor -> dynamic registry -> lossless.
/// A registered catch-all dynamic parser must NEVER shadow a known format —
/// native always wins for known shapes (anti-poisoning invariant).
#[test]
fn test_pinned_order_native_wins_over_registry() {
    use ulpf_ai::TieredPipeline;

    let pipeline = TieredPipeline::new();

    // Poison: a dynamic parser registered BEFORE the native line arrives. If
    // the registry were consulted first (or Tier-1b routed it), the product
    // vendor would come from the dynamic parser instead of the ASA extractor.
    let poison = ulpf_ai::ParserDefinition {
        vendor: "poison_vendor".into(),
        device_model: "catchall".into(),
        regex_pattern: r"^(?P<src_ip>.+)$".to_string(),
        action_mappings: Default::default(),
        sample_logs: vec![],
        confidence_score: 1.0,
        created_at: 0,
        regex_cache: std::sync::Arc::new(std::sync::OnceLock::new()),
    };
    {
        let reg_arc = pipeline.dynamic_registry();
        let mut reg = reg_arc.lock().unwrap();
        let key = reg.register(poison);
        assert_eq!(key, "poison_vendor:catchall");
        assert_eq!(reg.len(), 1);
    }

    let asa_line = "%ASA-6-302013: Built outbound TCP connection 1000672 for outside:203.0.113.54/25 (203.0.113.54/25) to inside:10.1.6.180/52369 (198.51.100.209/52369)";
    let activity = pipeline.process(asa_line);
    assert_eq!(
        activity.metadata.product.vendor_name, "Cisco",
        "native extractor must win for known formats — registry never poisons them"
    );
    assert_eq!(
        activity.src_endpoint.ip.as_deref(),
        Some("203.0.113.54"),
        "native ASA extraction must be what ran"
    );
}

/// A successful registry parse promotes a Tier-1b route: future same-shape
/// lines skip BOTH the Drain mutex and the full registry scan (observable:
/// the Drain hit counter stays 0 while repeat lines keep parsing via registry).
#[test]
fn test_dynamic_route_promotion_skips_drain() {
    use ulpf_ai::TieredPipeline;

    let pipeline = TieredPipeline::new();
    let samples = [
        "WAFNOVEL edge=prod tier=web src=10.1.1.1 sport=1111 dst=10.2.2.2 dport=8443 action=allow",
        "WAFNOVEL edge=prod tier=web src=10.1.1.2 sport=2222 dst=10.2.2.3 dport=8444 action=allow",
        "WAFNOVEL edge=prod tier=web src=10.1.1.3 sport=3333 dst=10.2.2.4 dport=8445 action=allow",
    ];

    // Register the parser up front (as the Tier-3 worker would after onboarding).
    let (parser_def, report) =
        Onboarder::generate_parser("novel_waf", "wafnovel-v1", &samples).expect("Synthesis");
    assert!(report.passed && report.match_percentage == 100.0);
    {
        let reg_arc = pipeline.dynamic_registry();
        let mut reg = reg_arc.lock().unwrap();
        let key = reg.register(parser_def);
        assert_eq!(key, "novel_waf:wafnovel-v1");
    }

    // Line 1: native Unknown, no route yet -> Drain (new cluster, no hit
    // count) + full registry scan + route installation.
    let a1 = pipeline.process(samples[0]);
    assert_eq!(
        a1.metadata.product.vendor_name, "novel_waf",
        "registry must parse unknown shapes"
    );
    assert_eq!(a1.src_endpoint.ip.as_deref(), Some("10.1.1.1"));

    // Lines 2-3: promoted route -> skip Drain entirely.
    let a2 = pipeline.process(samples[1]);
    assert_eq!(a2.src_endpoint.ip.as_deref(), Some("10.1.1.2"));
    let a3 = pipeline.process(samples[2]);
    assert_eq!(a3.src_endpoint.ip.as_deref(), Some("10.1.1.3"));

    let stats = pipeline.stats();
    assert_eq!(
        stats.tier2_drain_hits, 0,
        "promotion route must bypass the Drain mutex for repeat unknown shapes"
    );
}

/// Success-criterion-1 instrument: for every corpus line where the native
/// extractor fires, baseline `UniversalParser::parse` and
/// `TieredPipeline::process` must produce identical OCSF output modulo
/// `event_id`/`ingest_time`. Byte-exactness beats aggregate F1 ties at
/// catching wiring regressions.
#[test]
fn test_differential_baseline_vs_tiered() {
    use std::path::Path;
    use ulpf_ai::TieredPipeline;
    use ulpf_core::parser::classifier::VendorFormat;
    use ulpf_core::parser::UniversalParser;

    let raw_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/raw");
    let files = [
        "cisco_asa.log",
        "fortigate.log",
        "paloalto.log",
        "suricata.json",
        "pfsense.log",
    ];
    let mut corpus: Vec<String> = Vec::new();
    for file_name in files {
        let p = raw_dir.join(file_name);
        if !p.exists() {
            continue;
        }
        let text = std::fs::read_to_string(&p).expect("read corpus file");
        for l in text.lines() {
            let trimmed = l.trim().to_string();
            if !trimmed.is_empty() {
                corpus.push(trimmed);
            }
        }
    }
    assert!(!corpus.is_empty(), "corpus must exist under {:?}", raw_dir);

    let baseline = UniversalParser::new();
    let tiered = TieredPipeline::new();

    /// Strip per-event identity/clock fields so only semantic OCSF content
    /// compares. `time` joins `event_id`/`ingest_time` because extractors
    /// without a log timestamp (ASA, pfSense) stamp it with `Utc::now()` —
    /// two sequential parse calls land in different milliseconds. Log-derived
    /// timestamps (Suricata/PAN/FGT) are covered by the raw-preserving field
    /// checks; any real routing divergence still surfaces in the endpoints,
    /// disposition, product, and unmapped fields.
    fn normalize(a: &ulpf_core::schema::ocsf::NetworkActivity) -> serde_json::Value {
        let mut v = serde_json::to_value(a).expect("OCSF event must serialize");
        if let Some(obj) = v.as_object_mut() {
            obj.remove("time");
        }
        if let Some(obj) = v.get_mut("metadata").and_then(|m| m.as_object_mut()) {
            obj.remove("event_id");
            obj.remove("ingest_time");
        }
        v
    }

    let mut native_firing = 0usize;
    for line in &corpus {
        let format = baseline.classify(line);
        if format == VendorFormat::Unknown {
            continue;
        }
        native_firing += 1;
        match baseline.parse(line) {
            Ok(baseline_event) => {
                let tiered_event = tiered.process(line);
                assert_eq!(
                    normalize(&baseline_event),
                    normalize(&tiered_event),
                    "wiring divergence on native-firing line: {}",
                    line
                );
            }
            Err(_) => {
                // Native fired but its extractor errored: both sides must land
                // on the identical lossless fallback (modulo identity fields).
                let baseline_event = baseline.parse_lossless(line);
                let tiered_event = tiered.process(line);
                assert_eq!(
                    normalize(&baseline_event),
                    normalize(&tiered_event),
                    "lossless-fallback divergence on native-firing line: {}",
                    line
                );
            }
        }
    }
    assert!(
        native_firing > 1000,
        "differential must cover the native corpus (>1000 lines), got {}",
        native_firing
    );
}

// ============================================================================
// P5 — NULL-CORRECT AUDIT RULE (pre-registered)
// ============================================================================
// `None` on src/dst ip, ports, or protocol is audited as CORRECT only when the
// raw line carries no valid marker for that field. A marker with an absent
// field remains a failure — the rule masks nothing that evidence contradicts.

/// The honest-null families (ASA 113019, PAN ICMP CSV) must pass the marker
/// gates: no valid port marker, no IP-protocol marker, single IP.
#[test]
fn test_null_correct_honest_families_have_no_markers() {
    use ulpf_ai::EvaluatorEngine as E;

    // ASA 113019: exactly one IP (the peer -> src), no port keys, no
    // IP-protocol tokens ("Session Type: SSL" is an app protocol, not an
    // IP-layer marker).
    let a113019 = "<164>Sep 21 14:00:12 asa-dc-01 %ASA-4-113019: Group = RemoteAccess-Corp, Username = agarcia, IP = 203.0.113.163, Session disconnected. Session Type: SSL, Duration: 0h:39m";
    assert!(
        !E::raw_has_port_marker(a113019),
        "113019 carries no port evidence"
    );
    assert!(
        !E::raw_has_protocol_marker(a113019),
        "SSL is not an IP-protocol marker"
    );
    assert!(
        !E::raw_has_dst_ip_marker(a113019),
        "a single IP cannot evidence a second endpoint"
    );
    assert!(!E::raw_has_src_ip_marker(a113019));

    // PAN ICMP traffic (CSV): no kv port keys anywhere -> honest port null
    // even though the line is full of numbers (subnet/timestamp digits must
    // never count as port evidence).
    let icmp = "1,2026/09/21 14:00:01,001801000001,TRAFFIC,deny,2304,2026/09/21 14:00:00,192.168.1.19,203.0.113.87,198.51.100.32,203.0.113.87,Trust_to_Untrust,acme\\agarcia,,ping,vsys1,DMZ,WAN,ethernet1/1,ethernet1/2,default,,100412,1,0,0,0,0,0x400000,icmp,drop,4983547,454039,4529508,9510,2026/09/21 13:56:28,213,web-hosting,0,100000129,0x0";
    assert!(
        !E::raw_has_port_marker(icmp),
        "CSV without port keys is not port evidence"
    );
    // Both endpoints present -> the two-IP rule fires (irrelevant here: the
    // engine fills both, so the None branch is never consulted).
    assert!(E::raw_has_src_ip_marker(icmp));
    assert!(E::raw_has_dst_ip_marker(icmp));
}

/// Marker-present cases must STILL be failures — the rule can never launder an
/// extraction bug. Also pins the marker detectors' false-positive edges.
#[test]
fn test_null_correct_rule_still_fails_on_markers() {
    use ulpf_ai::EvaluatorEngine as E;

    // valid kv port value -> port marker
    assert!(E::raw_has_port_marker(
        "CEF:0|V|P|1|2|n|3|src=1.1.1.1 spt=443 dst=2.2.2.2 dpt=80"
    ));
    // INVALID port value (0) is not a valid marker -> ICMP sport=0 honest null
    assert!(!E::raw_has_port_marker(
        "date=2026-09-21 devname=FGT type=traffic sport=0 dport=0 proto=1"
    ));
    // interface:IP/PORT (ASA) is a marker...
    assert!(E::raw_has_port_marker(
        "%ASA-6-302013: Built outbound TCP connection 1 for outside:10.0.0.1/53 to inside:10.0.0.2/80"
    ));
    // ...but a bare CIDR must NOT be mistaken for one
    assert!(!E::raw_has_port_marker("route 10.0.0.0/24 via 192.168.1.1"));
    // bracketed IPv6 with port -> marker
    assert!(E::raw_has_port_marker(r#"flow from [2001:db8::1]:443"#));

    // role keys -> endpoint markers even without a second IP
    assert!(E::raw_has_dst_ip_marker(
        r#"{"src_ip":"1.1.1.1","dst_ip":"2.2.2.2"}"#
    ));
    assert!(E::raw_has_dst_ip_marker("srcip=1.1.1.1 dstip=9.9.9.9"));
    // two distinct IPv4s -> both roles evidenced
    assert!(E::raw_has_src_ip_marker("from 1.1.1.1 to 2.2.2.2"));
    // version strings / timestamps are NOT IPs
    assert!(!E::raw_has_dst_ip_marker(
        "CEF:0|Fortinet|FortiGate|v7.0.2|1|n|3|src=1.2.3.4"
    ));

    // protocol markers: kv key, name token, JSON key
    assert!(E::raw_has_protocol_marker("proto=6"));
    assert!(E::raw_has_protocol_marker("proto=17"));
    assert!(E::raw_has_protocol_marker(
        "%ASA-4-106023: Deny tcp src outside:1.1.1.1/1234 dst inside:2.2.2.2/80"
    ));
    assert!(E::raw_has_protocol_marker(r#"{"proto":"udp"}"#));
    // non-protocol names must never count
    assert!(!E::raw_has_protocol_marker(
        "Session disconnected. Session Type: SSL"
    ));
    assert!(!E::raw_has_protocol_marker("greater things coming"));
}

// ============================================================================
// P7 — CORPORA, SIDECAR GT, CLASS ANCHORS, ROBUSTNESS, FROZEN HOLDOUT
// ============================================================================

/// P7.1/P7.6: the committed adversarial corpus and its sidecar must agree
/// record-for-record, carry the plan-mandated schema, cover every mutation
/// class, and stay inside the ~1 MB committed budget.
#[test]
fn test_p7_adversarial_sidecar_schema() {
    use std::collections::HashSet;
    use std::path::Path;

    // Integration tests run from the package root, not the repo root.
    let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/raw");
    let log_path = base.join("adversarial/adversarial.log");
    let gt_path = base.join("adversarial/gt.jsonl");
    let log = std::fs::read_to_string(&log_path).expect("adversarial.log committed");
    let gt = std::fs::read_to_string(&gt_path).expect("gt sidecar committed");
    let raws: Vec<&str> = log.lines().filter(|l| !l.is_empty()).collect();
    let recs: Vec<serde_json::Value> = gt
        .lines()
        .map(|l| serde_json::from_str(l).expect("sidecar line is valid JSON"))
        .collect();
    assert_eq!(raws.len(), recs.len(), "log and sidecar are 1:1");
    assert!(raws.len() >= 500, "corpus must be substantial");

    const DIFFICULTIES: [&str; 6] = [
        "clean",
        "truncation",
        "relay",
        "encoding",
        "field-damage",
        "cardinality",
    ];
    const VENDORS: [&str; 5] = ["Cisco", "Fortinet", "Palo Alto", "pfSense", "Suricata"];
    const FIELD_KEYS: [&str; 5] = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"];
    let mut classes: HashSet<&str> = HashSet::new();

    for (raw, rec) in raws.iter().zip(recs.iter()) {
        assert_eq!(
            rec["raw"].as_str(),
            Some(*raw),
            "sidecar raw must be verbatim (overrides are keyed by it)"
        );
        for key in [
            "raw",
            "gt_vendor",
            "gt_template_tag",
            "gt_fields",
            "gt_disposition",
            "gt_protocol",
            "difficulty",
            "origin",
        ] {
            assert!(rec.get(key).is_some(), "record {} missing `{}`", raw, key);
        }
        assert!(VENDORS.contains(&rec["gt_vendor"].as_str().unwrap()));
        assert!(!rec["gt_template_tag"].as_str().unwrap().is_empty());
        assert!(!rec["origin"].as_str().unwrap().is_empty());
        let difficulty = rec["difficulty"].as_str().unwrap();
        assert!(
            DIFFICULTIES.contains(&difficulty),
            "bad difficulty {}",
            difficulty
        );
        classes.insert(difficulty);
        for key in FIELD_KEYS {
            assert!(
                rec["gt_fields"].get(key).is_some(),
                "gt_fields missing {}",
                key
            );
        }
    }
    for class in [
        "truncation",
        "relay",
        "encoding",
        "field-damage",
        "cardinality",
    ] {
        assert!(
            classes.contains(class),
            "mutation class {} not covered",
            class
        );
    }

    // Holdout sidecar: same schema, separate seed, vendors never seen in core.
    let hraw =
        std::fs::read_to_string(base.join("holdout/holdout.log")).expect("holdout.log committed");
    let hgt =
        std::fs::read_to_string(base.join("holdout/gt.jsonl")).expect("holdout sidecar committed");
    let hraws: Vec<&str> = hraw.lines().filter(|l| !l.is_empty()).collect();
    let hrecs: Vec<serde_json::Value> = hgt
        .lines()
        .map(|l| serde_json::from_str(l).expect("holdout sidecar valid"))
        .collect();
    assert_eq!(hraws.len(), hrecs.len());
    assert!(hraws.len() >= 100);
    let hvendors: HashSet<&str> = hrecs
        .iter()
        .map(|r| r["gt_vendor"].as_str().unwrap())
        .collect();
    for v in ["MikroTik", "Juniper", "ZypherFire"] {
        assert!(hvendors.contains(v), "holdout vendor {} missing", v);
    }

    // Plan P7.6: total committed corpus (logs + sidecars) ≈ ≤ 1 MB.
    let mut total = 0usize;
    for rel in [
        "adversarial/adversarial.log",
        "adversarial/gt.jsonl",
        "holdout/holdout.log",
        "holdout/gt.jsonl",
        "cisco_asa_vpn.log",
        "fortigate_utm.log",
        "paloalto_threat.log",
        "pfsense_ipv6.log",
    ] {
        let path = base.join(rel);
        total += std::fs::metadata(&path)
            .unwrap_or_else(|_| panic!("{} committed", path.display()))
            .len() as usize;
    }
    assert!(
        total < 1_200_000,
        "committed corpus {} bytes exceeds the ~1MB budget",
        total
    );
}

/// P7.2: refined in-line GT — FGT subtypes and PAN THREAT carry their own
/// grouping tags; ASA VPN/AAA verdict phrases map on both sides (this test
/// pins the evaluator half; `parser_tests` pins the engine half).
#[test]
fn test_p7_gt_tag_refinements_and_vpn_aaa_vocab() {
    use ulpf_ai::EvaluatorEngine;

    let dns = r#"<189>date=2026-09-21 time=14:00:07 devname="FGT-CORP-FW01" logid="0001000013" type="dns" subtype="forward" level="info" vd="root" srcip=10.0.0.5 srcport=51000 dstip=198.51.100.9 dstport=53 sessionid=1000123 action="blocked" proto=17 qtype=A qname="evil.example.net""#;
    let (v, tag, act) = EvaluatorEngine::extract_ground_truth(dns);
    assert_eq!(v, "Fortinet");
    assert_eq!(tag, "fortigate_dns");
    assert_eq!(act.as_deref(), Some("Blocked"));

    let utm = dns.replace(r#"type="dns""#, r#"type="utm""#);
    let (_, tag, _) = EvaluatorEngine::extract_ground_truth(&utm);
    assert_eq!(tag, "fortigate_utm");

    let appctrl = dns.replace(r#"type="dns""#, r#"type="app-ctrl""#);
    let (_, tag, _) = EvaluatorEngine::extract_ground_truth(&appctrl);
    assert_eq!(tag, "fortigate_appctrl");

    let traffic = dns.replace(r#"type="dns""#, r#"type="traffic""#);
    let (_, tag, _) = EvaluatorEngine::extract_ground_truth(&traffic);
    assert_eq!(tag, "fortigate_traffic", "core traffic tag is unchanged");

    // PAN THREAT rows get their own tag (traffic rows keep panos_traffic)
    let pan_threat = "1,2026/09/21 14:00:07,001801000099,THREAT,end,2304,2026/09/21 14:00:07,10.1.1.5,203.0.113.9,10.1.1.5,203.0.113.9,LAN_to_WAN,acme\\agarcia,,threat-scan,vsys1,LAN,WAN,ethernet1/1,ethernet1/2,default,,100412,1,49152,443,32768,443,0x400000,tcp,deny,512,256,768,4,2026/09/21 14:00:00,21,networking,0,100000155,0x0,192.168.0.0-192.168.255.255,US,0,612,8898,,0,0,0,0,vsys1,PA-5220-FW01,from-policy,,,0,0,0,,N/A,0,0,0,0";
    let (v, tag, act) = EvaluatorEngine::extract_ground_truth(pan_threat);
    assert_eq!(v, "Palo Alto");
    assert_eq!(tag, "panos_threat");
    assert_eq!(act.as_deref(), Some("Blocked"), "action column index 30");

    // ASA VPN/AAA shared verdict vocabulary (engine half in parser_tests)
    let aaa_ok = "<130>Sep 21 14:04:11 asa-vpn-gw01 %ASA-6-716059: Group = vpn-users, Username = jdoe, IP = 203.0.113.51, Successful login to server.";
    let (_, _, act) = EvaluatorEngine::extract_ground_truth(aaa_ok);
    assert_eq!(act.as_deref(), Some("Allowed"));

    let aaa_fail = "<164>Sep 21 14:04:12 asa-vpn-gw01 %ASA-4-716060: Group = vpn-users, Username = root, IP = 203.0.113.51, authentication failed.";
    let (_, _, act) = EvaluatorEngine::extract_ground_truth(aaa_fail);
    assert_eq!(act.as_deref(), Some("Blocked"));

    let vpn_ok = "<130>Sep 21 14:03:11 asa-vpn-gw01 %ASA-6-713041: Group = vpn-users, IP = 198.51.100.77, IPsec tunnel established.";
    let (_, _, act) = EvaluatorEngine::extract_ground_truth(vpn_ok);
    assert_eq!(act.as_deref(), Some("Allowed"));

    let vpn_fail = "<164>Sep 21 14:03:12 asa-vpn-gw01 %ASA-4-713172: Group = vpn-users, IP = 198.51.100.77, IPsec tunnel, authentication failed from gateway.";
    let (_, _, act) = EvaluatorEngine::extract_ground_truth(vpn_fail);
    assert_eq!(act.as_deref(), Some("Blocked"));

    // P8 merge rec #1 lockstep: GT must resolve `session disconnected` to
    // Allowed exactly like the engine fallback (`parser_tests.rs::test_asa_
    // fallback_session_disconnected_phrase`), failure phrases still first.
    let disc = "<130>Sep 21 14:05:00 asa-vpn-gw01 %ASA-6-713104: Group = vpn-users, IP = 198.51.100.77, Session disconnected.";
    let (_, _, act) = EvaluatorEngine::extract_ground_truth(disc);
    assert_eq!(
        act.as_deref(),
        Some("Allowed"),
        "GT must expect Allowed for a session-disconnect line"
    );

    let disc_fail = "<164>Sep 21 14:05:01 asa-vpn-gw01 %ASA-4-716060: Group = vpn-users, IP = 198.51.100.77, Session disconnected after authentication failed.";
    let (_, _, act) = EvaluatorEngine::extract_ground_truth(disc_fail);
    assert_eq!(
        act.as_deref(),
        Some("Blocked"),
        "failure phrase must outrank the disconnect phrase on the GT side too"
    );
}

/// P7.2 GA safety net: class partitions must never merge — kv `type=` values
/// (key-aware class anchors) and PAN's CSV-split bare TRAFFIC/THREAT tokens
/// (vocabulary anchors seen through `key="value"`).
#[test]
fn test_drain_class_partitions_never_merge() {
    let mut miner = DrainMiner::new(DrainConfig::default());

    // FGT: near-identical kv shape, same length node, sim ≈ 0.97 — only the
    // `type=` class value and action differ.
    let traffic = r#"<189>date=2026-09-21 time=14:00:05 devname="FGT-CORP-FW01" logid="0000000003" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.5.14 srcport=50470 dstip=198.51.100.22 dstport=3389 sessionid=1000230 action="accept" proto=6"#;
    let dns = r#"<189>date=2026-09-21 time=14:00:05 devname="FGT-CORP-FW01" logid="0001000013" type="dns" subtype="forward" level="notice" vd="root" srcip=192.168.5.14 srcport=50470 dstip=198.51.100.22 dstport=53 sessionid=1000230 action="blocked" proto=17"#;
    let traffic2 = traffic
        .replace("time=14:00:05", "time=14:00:09")
        .replace("srcip=192.168.5.14", "srcip=192.168.7.45");

    let r1 = miner.add_log(traffic);
    let r2 = miner.add_log(dns);
    let r3 = miner.add_log(&traffic2);
    assert_ne!(
        r1.cluster_id, r2.cluster_id,
        "type= class values (traffic vs dns) must never share a cluster"
    );
    assert_eq!(
        r1.cluster_id, r3.cluster_id,
        "same class value must not over-split"
    );

    // PAN CSV rows tokenize comma-free-of-whitespace into fused tokens; the
    // type token lands BARE at index 3 — TRAFFIC vs THREAT are anchored.
    let pan_traffic = "1,2026/09/21 14:00:01,001801000001,TRAFFIC,start,2304,2026/09/21 14:00:01,192.168.1.19,203.0.113.87,192.168.1.19,203.0.113.87,Trust_to_Untrust,acme\\agarcia,,ping,vsys1,DMZ,WAN,ethernet1/1,ethernet1/2,default,,100412,1,0,0,0,0,0x400000,icmp,allow,4983547,454039,4529508,9510,2026/09/21 13:56:28,213,web-hosting,0,100000129,0x0,192.168.0.0-192.168.255.255,US,0,612,8898,,0,0,0,0,vsys1,PA-5220-FW01,from-policy,,,0,0,0,,N/A,0,0,0,0";
    let pan_threat = pan_traffic
        .replace(",TRAFFIC,", ",THREAT,")
        .replace(",start,", ",end,");
    let p1 = miner.add_log(pan_traffic);
    let p2 = miner.add_log(&pan_threat);
    assert_ne!(
        p1.cluster_id, p2.cluster_id,
        "PAN TRAFFIC vs THREAT class tokens are anchors"
    );
}

/// P7.5: sidecar GT overrides are authoritative over in-line derivation —
/// a deliberately LYING sidecar must flip the audit outcome, proving the
/// override path is live (adversarial mutations destroy in-line markers,
/// so the sidecar is the only honest GT source there).
#[test]
fn test_p7_sidecar_gt_overrides_are_authoritative() {
    use ulpf_ai::evaluator::GtOverrides;
    use ulpf_ai::EvaluatorEngine;
    use ulpf_ai::SidecarGroundTruth;

    let corpus = vec![
        "<166>Sep 21 14:00:43 asa-edge-01 %ASA-6-302013: Built inbound TCP connection 1001322 for outside:203.0.113.137/993 (203.0.113.137/993) to inside:10.1.18.77/26375 (198.51.100.238/26375)".to_string(),
        "<166>Sep 21 14:00:58 asa-vpn-gw01 %ASA-6-302013: Built outbound TCP connection 1000734 for outside:198.51.100.50/1433 (198.51.100.50/1433) to inside:10.1.18.77/16288 (198.51.100.227/16288)".to_string(),
    ];

    let mut lying = GtOverrides::new();
    for raw in &corpus {
        lying.insert(
            raw.clone(),
            SidecarGroundTruth {
                raw: raw.clone(),
                gt_vendor: "Fortinet".into(), // engine says Cisco -> must FAIL
                gt_template_tag: "%ASA-6-302013:".into(),
                gt_fields: serde_json::json!({
                    "src_ip": null, "dst_ip": null,
                    "src_port": null, "dst_port": null, "protocol": null,
                }),
                gt_disposition: Some("Allowed".into()),
                gt_protocol: None,
                difficulty: "clean".into(),
                origin: "test:lying-sidecar".into(),
            },
        );
    }

    let report = EvaluatorEngine::evaluate_with_mode("tiered", &corpus, 1, 1, 100, &lying);
    let t = report.tiered_pipeline.as_ref().unwrap();
    assert_eq!(
        t.accuracy.vendor_classification_accuracy_pct, 0.0,
        "sidecar override must be authoritative (Cisco parsed, Fortinet GT)"
    );

    // Same corpus, no overrides: in-line GT agrees -> VCA 100.
    let clean =
        EvaluatorEngine::evaluate_with_mode("tiered", &corpus, 1, 1, 100, &GtOverrides::new());
    let t2 = clean.tiered_pipeline.as_ref().unwrap();
    assert_eq!(t2.accuracy.vendor_classification_accuracy_pct, 100.0);

    // Robustness block: both lines parse without panics and stay lossless;
    // all-null gt_fields leave nothing to grade (wrong=0, total=0).
    assert_eq!(t.robustness.lines_total, 2);
    assert_eq!(t.robustness.no_panic, 2);
    assert_eq!(t.robustness.lossless_ok, 2);
    assert_eq!(t.robustness.gt_fields_total, 0);
    assert_eq!(t.robustness.gt_fields_wrong, 0);
}

/// P7.5 null-vs-wrong discipline against explicit sidecar gt_fields:
/// matching values grade correct, honest nulls stay null, a WRONG non-null
/// counts strictly worse than a null.
#[test]
fn test_p7_robustness_null_vs_wrong_discipline() {
    use ulpf_ai::evaluator::GtOverrides;
    use ulpf_ai::EvaluatorEngine;
    use ulpf_ai::SidecarGroundTruth;

    let good = "<166>Sep 21 14:00:43 asa-edge-01 %ASA-6-302013: Built inbound TCP connection 1001322 for outside:203.0.113.137/993 (203.0.113.137/993) to inside:10.1.18.77/26375 (198.51.100.238/26375)".to_string();
    let corpus = vec![good.clone()];

    let mut ov = GtOverrides::new();
    ov.insert(
        good.clone(),
        SidecarGroundTruth {
            raw: good.clone(),
            gt_vendor: "Cisco".into(),
            gt_template_tag: "%ASA-6-302013:".into(),
            gt_fields: serde_json::json!({
                "src_ip": "203.0.113.137",
                "dst_ip": "10.1.18.77",
                "src_port": 993,
                "dst_port": 26375,
                "protocol": "tcp",
            }),
            gt_disposition: Some("Allowed".into()),
            gt_protocol: Some("tcp".into()),
            difficulty: "clean".into(),
            origin: "test:fields".into(),
        },
    );

    let report = EvaluatorEngine::evaluate_with_mode("tiered", &corpus, 1, 1, 100, &ov);
    let t = report.tiered_pipeline.as_ref().unwrap();
    assert_eq!(t.robustness.gt_fields_total, 5);
    assert_eq!(t.robustness.gt_fields_correct, 5, "all five fields grade");
    assert_eq!(t.robustness.gt_fields_wrong, 0);
    assert_eq!(t.robustness.gt_fields_null, 0);
    assert_eq!(t.robustness.format_recognized, 1);
    assert!(
        t.robustness.gt_wrong_by_key.is_empty(),
        "no wrongs -> empty by-key diagnostic"
    );

    // A WRONG non-null (GT says 994, engine extracts 993) is strictly worse
    // than an honest null — it must land in `wrong`, never `null`.
    let mut wrong_ov = ov.clone();
    wrong_ov.get_mut(&good).unwrap().gt_fields["src_port"] = serde_json::json!(994);
    let report2 = EvaluatorEngine::evaluate_with_mode("tiered", &corpus, 1, 1, 100, &wrong_ov);
    let t2 = report2.tiered_pipeline.as_ref().unwrap();
    assert_eq!(t2.robustness.gt_fields_wrong, 1);
    assert_eq!(t2.robustness.gt_fields_correct, 4);
    assert_eq!(t2.robustness.gt_fields_null, 0);
    assert_eq!(
        t2.robustness.gt_wrong_by_key.get("src_port"),
        Some(&1),
        "by-key diagnostic records exactly which field contradicted"
    );
    assert!(
        !t2.robustness.gt_wrong_by_key.contains_key("dst_ip"),
        "only the contradicting key is recorded"
    );
}

/// Full-dataset protocol parity (generated on demand via
/// `gen_adversarial.py --full N`; skipped when absent so the suite stays
/// hermetic). Grades sidecar `gt_fields.protocol` against the engine's
/// `protocol_name` line-by-line — this is what localizes the aggregate
/// `gt_wrong_by_key` count to specific families.
#[test]
fn test_full_dataset_protocol_parity_when_generated() {
    use ulpf_core::parser::UniversalParser;
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/raw/full");
    let gt_path = dir.join("gt.jsonl");
    if !gt_path.exists() {
        return; // generated on demand — nothing to grade
    }
    let text = std::fs::read_to_string(&gt_path).expect("read full sidecar");
    let parser = UniversalParser::new();
    let mut mismatches: Vec<String> = Vec::new();
    let mut graded = 0usize;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let rec: serde_json::Value = serde_json::from_str(line).expect("jsonl");
        let exp = rec["gt_fields"]
            .get("protocol")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        if exp.is_null() {
            continue;
        }
        graded += 1;
        let raw = rec["raw"].as_str().expect("raw string");
        let act = parser.parse(raw).expect("parse full-dataset line");
        let obs = act
            .connection_info
            .protocol_name
            .clone()
            .map(serde_json::Value::String)
            .unwrap_or(serde_json::Value::Null);
        let ok = match (&exp, &obs) {
            (serde_json::Value::String(a), serde_json::Value::String(b)) => {
                a.eq_ignore_ascii_case(b)
            }
            _ => exp == obs,
        };
        if !ok {
            mismatches.push(format!(
                "origin={} exp={} obs={} raw={}",
                rec.get("origin").and_then(|v| v.as_str()).unwrap_or("?"),
                exp,
                obs,
                raw
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{}/{} protocol mismatches; first up to 5:\n{}",
        mismatches.len(),
        graded,
        mismatches[..mismatches.len().min(5)].join("\n")
    );
}

/// P7.3/P8: the novel-vendor holdout is FROZEN — never executed until the
/// final P8 freeze (plan §3 P7.3). Run at freeze via
/// `cargo test -p ulpf-ai -- --ignored test_holdout`.
#[test]
#[ignore = "holdout frozen until the P8 final freeze"]
fn test_holdout_novelty_end_to_end_at_freeze() {
    use ulpf_ai::pipeline::TieredPipeline;
    use ulpf_core::parser::compute_sha256;

    let raws = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data/raw/holdout/holdout.log"),
    )
    .expect("holdout.log committed");
    let lines: Vec<String> = raws
        .lines()
        .filter(|l| !l.is_empty())
        .map(|s| s.to_string())
        .collect();
    assert!(!lines.is_empty());

    let pipeline = TieredPipeline::new();
    let mut novel_reached_tier3 = 0usize;
    for raw in &lines {
        let activity = pipeline.process(raw); // must never panic
        assert_eq!(
            activity.metadata.raw_hash,
            compute_sha256(raw.as_bytes()),
            "holdout line must stay lossless: {}",
            raw
        );
        novel_reached_tier3 += 1;
    }
    let stats = pipeline.stats();
    assert!(
        stats.tier3_laya_dispatches > 0 || novel_reached_tier3 > 0,
        "novel formats must traverse the pipeline without crashing"
    );
}

// ============================================================================
// DUEL BASELINE — `anchors_enabled: false` MUST reproduce stock Drain
// ============================================================================
// The scorecard duel grades vanilla Drain (literature baseline) against the
// 3-tier pipeline on the same tokenizer; the ONLY intended difference is the
// anchor subsystem. Disabling it must turn off all three ULPF hooks —
// anchor vocabulary, syslog-tag homogeneity (P6.1) and the key-aware class
// partition (P7.2) — so the baseline merges what stock Drain would merge.
// Each pair below is shaped to differ ONLY in the hook under test.
#[test]
fn test_drain_anchors_enabled_toggle() {
    let vanilla_cfg = DrainConfig {
        anchors_enabled: false,
        ..Default::default()
    };

    // Hook 1: anchor vocabulary (bare ALLOW/DENY verbs, ~91% token overlap).
    let allow = "FIREWALL connection 1001 protocol TCP action ALLOW src 192.168.1.10 dst 10.0.0.1";
    let deny = "FIREWALL connection 1002 protocol TCP action DENY src 192.168.1.20 dst 10.0.0.2";
    let mut vanilla = DrainMiner::new(vanilla_cfg.clone());
    let v1 = vanilla.add_log(allow);
    let v2 = vanilla.add_log(deny);
    assert_eq!(
        v1.cluster_id, v2.cluster_id,
        "vanilla (anchors off) must merge the near-identical ALLOW/DENY pair"
    );
    let mut anchored = DrainMiner::new(DrainConfig::default());
    let a1 = anchored.add_log(allow);
    let a2 = anchored.add_log(deny);
    assert_ne!(
        a1.cluster_id, a2.cluster_id,
        "default config must still split ALLOW/DENY (invariant #3)"
    );

    // Hook 2: syslog-tag homogeneity (P6.1) — identical body, different
    // `%ASA-6-*` message code; no anchor-vocab word differs on either side,
    // so only the tag check can split the default config.
    let built =
        "<166>Sep 24 10:00:00 cisco-asa %ASA-6-302013: connection from 198.51.100.7 to 10.1.2.3";
    let reset =
        "<166>Sep 24 10:00:00 cisco-asa %ASA-6-302015: connection from 198.51.100.7 to 10.1.2.3";
    let mut vanilla = DrainMiner::new(vanilla_cfg.clone());
    let v1 = vanilla.add_log(built);
    let v2 = vanilla.add_log(reset);
    assert_eq!(
        v1.cluster_id, v2.cluster_id,
        "vanilla has no tag homogeneity: differing message codes may merge"
    );
    let mut anchored = DrainMiner::new(DrainConfig::default());
    let a1 = anchored.add_log(built);
    let a2 = anchored.add_log(reset);
    assert_ne!(
        a1.cluster_id, a2.cluster_id,
        "default config must keep clusters syslog-tag-homogeneous"
    );

    // Hook 3: key-aware class partition (P7.2) — same `type=` key, values
    // outside the anchor vocabulary (forward vs proxy), everything else equal.
    // The kv pair sits past the 2-token prefix path so both lines reach the
    // same leaf; only the class rule can split them.
    let traffic = r#"devid="FGT9" direction inbound type="forward" srcip=10.0.0.1 dstip=10.0.0.2"#;
    let proxy = r#"devid="FGT9" direction inbound type="proxy" srcip=10.0.0.1 dstip=10.0.0.2"#;
    let mut vanilla = DrainMiner::new(vanilla_cfg);
    let v1 = vanilla.add_log(traffic);
    let v2 = vanilla.add_log(proxy);
    assert_eq!(
        v1.cluster_id, v2.cluster_id,
        "vanilla ignores key=value class discriminators"
    );
    let mut anchored = DrainMiner::new(DrainConfig::default());
    let a1 = anchored.add_log(traffic);
    let a2 = anchored.add_log(proxy);
    assert_ne!(
        a1.cluster_id, a2.cluster_id,
        "default config must split same-key/different-value class tokens"
    );
}
