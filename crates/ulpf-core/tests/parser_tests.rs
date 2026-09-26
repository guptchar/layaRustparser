use sha2::{Digest, Sha256};
use std::time::Instant;
use uuid::Uuid;

use ulpf_core::{activity_id, disposition, Classifier, UniversalParser, VendorFormat};

#[test]
fn test_cisco_asa_parsing_suite() {
    let parser = UniversalParser::new();

    // 1. Built inbound UDP connection (%ASA-6-302013)
    let sample_built_udp = "<166>Sep 21 14:00:00 asa %ASA-6-302013: Built inbound UDP connection 12345 for outside:192.168.1.50/51234 (192.168.1.50/51234) to inside:10.0.0.1/53 (10.0.0.1/53)";
    let event = parser
        .parse(sample_built_udp)
        .expect("Failed to parse Cisco ASA built UDP");

    assert_eq!(event.category_uid, 4);
    assert_eq!(event.class_uid, 4001);
    assert_eq!(event.type_uid, 400101);
    assert_eq!(event.activity_id, activity_id::OPEN);
    assert_eq!(event.activity_name, "Open");
    assert_eq!(event.disposition, disposition::ALLOWED);
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("192.168.1.50"));
    assert_eq!(event.src_endpoint.port, Some(51234));
    assert_eq!(event.src_endpoint.interface.as_deref(), Some("outside"));
    assert_eq!(event.dst_endpoint.ip.as_deref(), Some("10.0.0.1"));
    assert_eq!(event.dst_endpoint.port, Some(53));
    assert_eq!(event.dst_endpoint.interface.as_deref(), Some("inside"));
    assert_eq!(event.connection_info.protocol_name.as_deref(), Some("UDP"));
    assert_eq!(event.connection_info.protocol_num, Some(17));
    assert_eq!(event.connection_info.direction.as_deref(), Some("Inbound"));
    assert_eq!(event.metadata.product.vendor_name, "Cisco");
    assert_eq!(event.metadata.raw_data, sample_built_udp);
    assert_eq!(
        event.metadata.raw_hash,
        hex::encode(Sha256::digest(sample_built_udp.as_bytes()))
    );
    assert_eq!(
        Uuid::parse_str(&event.metadata.event_id)
            .unwrap()
            .get_version_num(),
        7
    );

    // 2. Built outbound TCP connection (%ASA-6-302013)
    let sample_built_tcp = "%ASA-6-302013: Built outbound TCP connection 98765 for inside:10.0.0.5/49152 (10.0.0.5/49152) to outside:203.0.113.10/443 (203.0.113.10/443)";
    let event_tcp = parser
        .parse(sample_built_tcp)
        .expect("Failed to parse Cisco ASA built TCP");
    assert_eq!(event_tcp.activity_id, activity_id::OPEN);
    assert_eq!(
        event_tcp.connection_info.direction.as_deref(),
        Some("Outbound")
    );
    assert_eq!(
        event_tcp.connection_info.protocol_name.as_deref(),
        Some("TCP")
    );
    assert_eq!(event_tcp.connection_info.protocol_num, Some(6));

    // 3. Teardown connection (%ASA-6-302014)
    let sample_teardown = "%ASA-6-302014: Teardown TCP connection 98765 for inside:10.0.0.5/49152 to outside:203.0.113.10/443 duration 0:00:30 bytes 1234 TCP FINs";
    let event_td = parser
        .parse(sample_teardown)
        .expect("Failed to parse Cisco ASA teardown");
    assert_eq!(event_td.activity_id, activity_id::CLOSE);
    assert_eq!(event_td.activity_name, "Close");
    assert_eq!(event_td.disposition, disposition::ALLOWED);
    assert_eq!(
        event_td.traffic.as_ref().and_then(|t| t.bytes_out),
        Some(1234)
    );
    assert_eq!(event_td.metadata.raw_data, sample_teardown);

    // 4. Deny packet (%ASA-4-106023)
    let sample_deny = "%ASA-4-106023: Deny tcp src outside:198.51.100.25/1234 dst inside:10.0.0.10/80 by access-group \"outside_in\" [0x0, 0x0]";
    let event_deny = parser
        .parse(sample_deny)
        .expect("Failed to parse Cisco ASA deny");
    assert_eq!(event_deny.activity_id, activity_id::OTHER);
    assert_eq!(event_deny.disposition, disposition::BLOCKED);
    assert_eq!(event_deny.src_endpoint.ip.as_deref(), Some("198.51.100.25"));
    assert_eq!(event_deny.dst_endpoint.ip.as_deref(), Some("10.0.0.10"));

    // 5. Drop / Denied (%ASA-2-106001)
    let sample_drop = "%ASA-2-106001: Inbound TCP connection denied from 198.51.100.5/5555 to 10.0.0.2/80 flags SYN on interface outside";
    let event_drop = parser
        .parse(sample_drop)
        .expect("Failed to parse Cisco ASA drop");
    assert_eq!(event_drop.activity_id, activity_id::OTHER);
    assert_eq!(event_drop.disposition, disposition::DROPPED);
    assert_eq!(event_drop.src_endpoint.ip.as_deref(), Some("198.51.100.5"));
    assert_eq!(event_drop.dst_endpoint.ip.as_deref(), Some("10.0.0.2"));
    assert_eq!(
        event_drop.src_endpoint.interface.as_deref(),
        Some("outside")
    );
}

#[test]
fn test_fortinet_parsing_suite() {
    let parser = UniversalParser::new();

    // 1. Traffic Accept Forward event
    let sample_fgt = r#"date=2023-10-15 time=10:20:30 devname="FGT60D" devid="FGT60D12345" type="traffic" subtype="forward" level="notice" vd="root" srcip=192.168.1.100 srcport=54321 srcintf="port1" dstip=203.0.113.5 dstport=443 dstintf="port2" proto=6 action="accept" policyid=1 sentbyte=2048 rcvdbyte=4096 sentpkt=10 rcvdpkt=15 app="HTTPS""#;
    let event = parser
        .parse(sample_fgt)
        .expect("Failed to parse FortiGate log");

    assert_eq!(event.category_uid, 4);
    assert_eq!(event.class_uid, 4001);
    assert_eq!(event.type_uid, 400103);
    assert_eq!(event.activity_id, activity_id::TRAFFIC_FLOW);
    assert_eq!(event.disposition, disposition::ALLOWED);
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("192.168.1.100"));
    assert_eq!(event.src_endpoint.port, Some(54321));
    assert_eq!(event.src_endpoint.interface.as_deref(), Some("port1"));
    assert_eq!(event.dst_endpoint.ip.as_deref(), Some("203.0.113.5"));
    assert_eq!(event.dst_endpoint.port, Some(443));
    assert_eq!(event.dst_endpoint.interface.as_deref(), Some("port2"));
    assert_eq!(event.connection_info.protocol_num, Some(6));
    assert_eq!(event.connection_info.protocol_name.as_deref(), Some("TCP"));

    let traffic = event.traffic.expect("Expected traffic metrics");
    assert_eq!(traffic.bytes_out, Some(2048));
    assert_eq!(traffic.bytes_in, Some(4096));
    assert_eq!(traffic.packets_out, Some(10));
    assert_eq!(traffic.packets_in, Some(15));

    assert_eq!(event.metadata.product.vendor_name, "Fortinet");
    assert_eq!(event.metadata.raw_data, sample_fgt);
    assert_eq!(
        event.metadata.raw_hash,
        hex::encode(Sha256::digest(sample_fgt.as_bytes()))
    );

    // 2. Deny event
    let sample_fgt_deny = r#"date=2023-10-15 time=10:20:30 devname="FGT60D" type="traffic" srcip=10.0.0.1 srcport=12345 dstip=10.0.0.2 dstport=80 proto=6 action="deny""#;
    let event_deny = parser
        .parse(sample_fgt_deny)
        .expect("Failed to parse FortiGate deny");
    assert_eq!(event_deny.activity_id, activity_id::OTHER);
    assert_eq!(event_deny.disposition, disposition::BLOCKED);

    // 3. Close event
    let sample_fgt_close = r#"date=2023-10-15 time=10:20:30 devname="FGT60D" type="traffic" srcip=10.0.0.1 srcport=12345 dstip=10.0.0.2 dstport=80 proto=6 action="close""#;
    let event_close = parser
        .parse(sample_fgt_close)
        .expect("Failed to parse FortiGate close");
    assert_eq!(event_close.activity_id, activity_id::CLOSE);
    assert_eq!(event_close.disposition, disposition::ALLOWED);
}

#[test]
fn test_palo_alto_parsing_suite() {
    let parser = UniversalParser::new();

    // 1. PAN-OS Traffic Start CSV
    let sample_pan = "1,2023/10/15 10:20:30,001801000000,TRAFFIC,start,0,2023/10/15 10:20:30,192.168.1.50,203.0.113.25,192.168.1.50,203.0.113.25,allow-web,user1,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,log-forwarding,0,12345,1,54321,80,0,0,0x0,tcp,allow,1024,512,512,10,2023/10/15 10:20:30,15,any,0,1234567,0x0";
    let event = parser
        .parse(sample_pan)
        .expect("Failed to parse Palo Alto PAN-OS CSV");

    assert_eq!(event.category_uid, 4);
    assert_eq!(event.class_uid, 4001);
    assert_eq!(event.type_uid, 400101);
    assert_eq!(event.activity_id, activity_id::OPEN);
    assert_eq!(event.disposition, disposition::ALLOWED);
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("192.168.1.50"));
    assert_eq!(event.src_endpoint.port, Some(54321));
    assert_eq!(event.src_endpoint.zone.as_deref(), Some("trust"));
    assert_eq!(event.src_endpoint.interface.as_deref(), Some("ethernet1/2"));
    assert_eq!(event.dst_endpoint.ip.as_deref(), Some("203.0.113.25"));
    assert_eq!(event.dst_endpoint.port, Some(80));
    assert_eq!(event.dst_endpoint.zone.as_deref(), Some("untrust"));
    assert_eq!(event.dst_endpoint.interface.as_deref(), Some("ethernet1/1"));
    assert_eq!(event.connection_info.protocol_name.as_deref(), Some("TCP"));
    assert_eq!(event.connection_info.protocol_num, Some(6));

    let traffic = event.traffic.expect("Expected traffic metrics");
    assert_eq!(traffic.bytes_out, Some(512));
    assert_eq!(traffic.bytes_in, Some(512));

    assert_eq!(event.metadata.product.vendor_name, "Palo Alto Networks");
    assert_eq!(event.metadata.raw_data, sample_pan);
    assert_eq!(
        event.metadata.raw_hash,
        hex::encode(Sha256::digest(sample_pan.as_bytes()))
    );

    // 2. PAN-OS Traffic Drop with Syslog header
    let sample_pan_drop = "Oct 15 10:20:30 my-pan-fw 1,2023/10/15 10:20:30,001801000000,TRAFFIC,drop,0,2023/10/15 10:20:30,10.0.0.5,1.1.1.1,10.0.0.5,1.1.1.1,block-external,,,dns,vsys1,inside,outside,eth1,eth2,default,0,999,1,40000,53,0,0,0x0,udp,drop,0,0,0,1";
    let event_drop = parser
        .parse(sample_pan_drop)
        .expect("Failed to parse Palo Alto drop");
    assert_eq!(event_drop.activity_id, activity_id::OTHER);
    assert_eq!(event_drop.disposition, disposition::DROPPED);
    assert_eq!(event_drop.src_endpoint.ip.as_deref(), Some("10.0.0.5"));
    assert_eq!(event_drop.src_endpoint.port, Some(40000));
    assert_eq!(event_drop.dst_endpoint.ip.as_deref(), Some("1.1.1.1"));
    assert_eq!(event_drop.dst_endpoint.port, Some(53));
    assert_eq!(
        event_drop.connection_info.protocol_name.as_deref(),
        Some("UDP")
    );
    assert_eq!(event_drop.connection_info.protocol_num, Some(17));
}

#[test]
fn test_suricata_parsing_suite() {
    let parser = UniversalParser::new();

    // 1. Suricata Alert EVE-JSON
    let sample_alert = r#"{"timestamp":"2023-10-15T10:20:30.123456+0000","flow_id":1234567890,"in_iface":"eth0","event_type":"alert","src_ip":"192.168.1.10","src_port":54321,"dest_ip":"203.0.113.20","dest_port":80,"proto":"TCP","alert":{"action":"blocked","signature":"ET SCAN Potential SSH Scan","category":"Attempted Information Leak","severity":2}}"#;
    let event = parser
        .parse(sample_alert)
        .expect("Failed to parse Suricata alert");

    assert_eq!(event.category_uid, 4);
    assert_eq!(event.class_uid, 4001);
    assert_eq!(event.type_uid, 400199);
    assert_eq!(event.activity_id, activity_id::OTHER);
    assert_eq!(event.disposition, disposition::BLOCKED);
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("192.168.1.10"));
    assert_eq!(event.src_endpoint.port, Some(54321));
    assert_eq!(event.src_endpoint.interface.as_deref(), Some("eth0"));
    assert_eq!(event.dst_endpoint.ip.as_deref(), Some("203.0.113.20"));
    assert_eq!(event.dst_endpoint.port, Some(80));
    assert_eq!(event.connection_info.protocol_name.as_deref(), Some("TCP"));
    assert_eq!(event.connection_info.protocol_num, Some(6));

    let unmapped = event.unmapped.expect("Expected unmapped alert metadata");
    assert_eq!(
        unmapped.get("alert_signature").map(|s| s.as_str()),
        Some("ET SCAN Potential SSH Scan")
    );

    assert_eq!(event.metadata.product.vendor_name, "OISF");
    assert_eq!(event.metadata.product.name, "Suricata");
    assert_eq!(event.metadata.raw_data, sample_alert);
    assert_eq!(
        event.metadata.raw_hash,
        hex::encode(Sha256::digest(sample_alert.as_bytes()))
    );

    // 2. Suricata Flow Closed event
    let sample_flow = r#"{"timestamp":"2023-10-15T10:20:30.123456+0000","flow_id":9876543210,"in_iface":"eth0","event_type":"flow","src_ip":"10.0.0.5","src_port":49152,"dest_ip":"198.51.100.1","dest_port":443,"proto":"TCP","flow":{"pkts_toserver":12,"pkts_toclient":18,"bytes_toserver":1500,"bytes_toclient":8500,"state":"closed","action":"pass"}}"#;
    let event_flow = parser
        .parse(sample_flow)
        .expect("Failed to parse Suricata flow");
    assert_eq!(event_flow.activity_id, activity_id::CLOSE);
    assert_eq!(event_flow.disposition, disposition::ALLOWED);
    let traffic = event_flow.traffic.expect("Expected traffic metrics");
    assert_eq!(traffic.bytes_out, Some(1500));
    assert_eq!(traffic.bytes_in, Some(8500));
    assert_eq!(traffic.packets_out, Some(12));
    assert_eq!(traffic.packets_in, Some(18));
}

#[test]
fn test_pfsense_parsing_suite() {
    let parser = UniversalParser::new();

    // 1. pfSense IPv4 Pass
    let sample_pfsense = "filterlog: 5,,,1000000103,em0,match,pass,in,4,0x0,,64,12345,0,none,6,tcp,60,192.168.1.50,203.0.113.10,54321,443,0,S,123456,,1024,,";
    let event = parser
        .parse(sample_pfsense)
        .expect("Failed to parse pfSense pass");

    assert_eq!(event.category_uid, 4);
    assert_eq!(event.class_uid, 4001);
    assert_eq!(event.type_uid, 400103);
    assert_eq!(event.activity_id, activity_id::TRAFFIC_FLOW);
    assert_eq!(event.disposition, disposition::ALLOWED);
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("192.168.1.50"));
    assert_eq!(event.src_endpoint.port, Some(54321));
    assert_eq!(event.src_endpoint.interface.as_deref(), Some("em0"));
    assert_eq!(event.dst_endpoint.ip.as_deref(), Some("203.0.113.10"));
    assert_eq!(event.dst_endpoint.port, Some(443));
    assert_eq!(event.connection_info.protocol_name.as_deref(), Some("TCP"));
    assert_eq!(event.connection_info.protocol_num, Some(6));
    assert_eq!(event.connection_info.direction.as_deref(), Some("Inbound"));

    assert_eq!(event.metadata.product.vendor_name, "Netgate");
    assert_eq!(event.metadata.raw_data, sample_pfsense);
    assert_eq!(
        event.metadata.raw_hash,
        hex::encode(Sha256::digest(sample_pfsense.as_bytes()))
    );

    // 2. pfSense IPv4 Block with syslog prefix
    let sample_pfsense_block = "Oct 15 10:20:30 pfSense filterlog[12345]: 4,,,1000000101,igb0,match,block,in,4,0x0,,128,5432,0,none,17,udp,40,10.0.0.15,8.8.8.8,51234,53,20";
    let event_block = parser
        .parse(sample_pfsense_block)
        .expect("Failed to parse pfSense block");
    assert_eq!(event_block.activity_id, activity_id::OTHER);
    assert_eq!(event_block.disposition, disposition::BLOCKED);
    assert_eq!(event_block.src_endpoint.ip.as_deref(), Some("10.0.0.15"));
    assert_eq!(event_block.src_endpoint.port, Some(51234));
    assert_eq!(event_block.src_endpoint.interface.as_deref(), Some("igb0"));
    assert_eq!(event_block.dst_endpoint.ip.as_deref(), Some("8.8.8.8"));
    assert_eq!(event_block.dst_endpoint.port, Some(53));
    assert_eq!(
        event_block.connection_info.protocol_name.as_deref(),
        Some("UDP")
    );
    assert_eq!(event_block.connection_info.protocol_num, Some(17));
}

#[test]
fn test_lossless_preservation_and_cryptographic_hashes() {
    let parser = UniversalParser::new();
    let samples = [
        "%ASA-6-302013: Built inbound UDP connection 123 for outside:1.1.1.1/53 to inside:2.2.2.2/53",
        r#"date=2023-10-15 time=10:20:30 devname="FGT60D" type="traffic" srcip=1.1.1.1 srcport=80 dstip=2.2.2.2 dstport=80 proto=6 action="accept""#,
        "1,2023/10/15 10:20:30,001801000000,TRAFFIC,drop,0,2023/10/15 10:20:30,1.1.1.1,2.2.2.2,1.1.1.1,2.2.2.2,rule1,,,app,vsys1,z1,z2,eth1,eth2,def,0,1,1,10,20,0,0,0,tcp,drop,0,0,0,1",
        r#"{"timestamp":"2023-10-15T10:20:30.123456+0000","event_type":"alert","src_ip":"1.1.1.1","dest_ip":"2.2.2.2","proto":"TCP","alert":{"action":"blocked"}}"#,
        "filterlog: 1,,,100,em0,match,pass,in,4,0,,64,1,0,none,6,tcp,60,1.1.1.1,2.2.2.2,1234,80,0,S,1,,10,,",
    ];

    for raw in samples {
        let event = parser.parse(raw).expect("Parsing must succeed");

        // 100% exact raw log preservation
        assert_eq!(
            event.metadata.raw_data, raw,
            "Raw log line must be 100% byte-for-byte preserved"
        );

        // SHA-256 match
        let expected_hash = hex::encode(Sha256::digest(raw.as_bytes()));
        assert_eq!(
            event.metadata.raw_hash, expected_hash,
            "Raw log SHA-256 digest must match mathematically"
        );

        // UUIDv7 verification
        let parsed_uuid =
            Uuid::parse_str(&event.metadata.event_id).expect("Event ID must be a valid UUID");
        assert_eq!(
            parsed_uuid.get_version_num(),
            7,
            "Event ID must be UUIDv7 time-ordered"
        );

        // OCSF 1.3 standard contract
        assert_eq!(event.category_uid, 4, "Category UID must be 4");
        assert_eq!(event.class_uid, 4001, "Class UID must be 4001");
        assert_eq!(
            event.type_uid,
            4001 * 100 + event.activity_id as u32,
            "Type UID must follow class_uid * 100 + activity_id"
        );
    }
}

#[test]
fn test_classification_sub_microsecond_benchmark() {
    let classifier = Classifier::new();
    let samples = [
        "<166>Sep 21 14:00:00 asa %ASA-6-302013: Built inbound UDP connection",
        r#"date=2023-10-15 time=10:20:30 devname="FGT60D" type="traffic" srcip=1.1.1.1"#,
        "1,2023/10/15 10:20:30,001801000000,TRAFFIC,drop,0,2023/10/15 10:20:30,10.0.0.1,10.0.0.2",
        r#"{"timestamp":"2023-10-15T10:20:30.123456+0000","event_type":"alert"}"#,
        "Oct 15 10:20:30 pfSense filterlog[12345]: 5,,,1000000103,em0,match,pass,in,4",
    ];

    let iterations = 20_000;
    let start = Instant::now();

    for _ in 0..iterations {
        for sample in &samples {
            let format = classifier.classify(sample);
            assert_ne!(format, VendorFormat::Unknown);
        }
    }

    let elapsed = start.elapsed();
    let total_operations = iterations * samples.len();
    let per_op = elapsed / (total_operations as u32);

    println!(
        "Total operations: {}, elapsed: {:?}, per classification: {:?}",
        total_operations, elapsed, per_op
    );
    assert!(
        per_op.as_nanos() < 2_000,
        "Classification should take < 2 microseconds per log line (took {:?})",
        per_op
    );
}

#[test]
fn test_fallback_lossless_parsing_for_unknown_log() {
    let parser = UniversalParser::new();
    let unknown_log = "UNKNOWN PROTOCOL LINE 12345 HELLO WORLD";
    let event = parser.parse_lossless(unknown_log);

    assert_eq!(event.metadata.raw_data, unknown_log);
    assert_eq!(
        event.metadata.raw_hash,
        hex::encode(Sha256::digest(unknown_log.as_bytes()))
    );
    assert_eq!(
        Uuid::parse_str(&event.metadata.event_id)
            .unwrap()
            .get_version_num(),
        7
    );
    assert_eq!(event.metadata.product.vendor_name, "Unknown");
}

#[test]
fn test_cef_parsing_suite() {
    let parser = UniversalParser::new();

    // Classification: CEF: header wins (vendor-neutral envelope).
    let sample_accept = "CEF:0|Fortinet|FortiGate|v7.0.2|0000000019|traffic:forward accept|3|deviceExternalId=FGT200F581900120 src=192.168.1.146 spt=25297 dst=203.0.113.207 dpt=80 proto=6 act=accept cat=traffic:forward cs1=vdom-dmz cs1Label=vd cs2=port2 cs2Label=srcintf cs3=dmz cs3Label=dstintf cn1=5 cn1Label=policyid app=HTTP in=485401 out=1176097 dvchost=FGT-DC-EDGE";
    assert_eq!(parser.classify(sample_accept), VendorFormat::Cef);

    // 1. act=accept -> Allowed (GT CEF branch parity)
    let event = parser.parse(sample_accept).expect("parse cef accept");
    assert_eq!(event.category_uid, 4);
    assert_eq!(event.class_uid, 4001);
    assert_eq!(event.type_uid, 400103, "accept -> TRAFFIC_FLOW type_uid");
    assert_eq!(event.activity_id, ulpf_core::activity_id::TRAFFIC_FLOW);
    assert_eq!(event.disposition, disposition::ALLOWED);
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("192.168.1.146"));
    assert_eq!(event.src_endpoint.port, Some(25297));
    assert_eq!(event.dst_endpoint.ip.as_deref(), Some("203.0.113.207"));
    assert_eq!(event.dst_endpoint.port, Some(80));
    assert_eq!(event.connection_info.protocol_num, Some(6));
    assert_eq!(event.connection_info.protocol_name.as_deref(), Some("TCP"));
    // Vendor comes from CEF header field 2 — never hardcoded.
    assert_eq!(event.metadata.product.vendor_name, "Fortinet");
    assert_eq!(event.metadata.product.name, "FortiGate");
    assert_eq!(event.metadata.product.version.as_deref(), Some("v7.0.2"));
    assert_eq!(event.metadata.raw_data, sample_accept);
    assert_eq!(
        event.metadata.raw_hash,
        hex::encode(Sha256::digest(sample_accept.as_bytes())),
        "raw must be preserved byte-for-byte (SHA-256)"
    );
    assert_eq!(
        Uuid::parse_str(&event.metadata.event_id)
            .unwrap()
            .get_version_num(),
        7
    );
    let unmapped = event.unmapped.as_ref().expect("unmapped present");
    assert_eq!(
        unmapped.get("cef_name").map(String::as_str),
        Some("traffic:forward accept")
    );
    assert_eq!(
        unmapped.get("cef_signature_id").map(String::as_str),
        Some("0000000019")
    );
    assert_eq!(unmapped.get("cef_severity").map(String::as_str), Some("3"));
    assert_eq!(
        unmapped.get("dvchost").map(String::as_str),
        Some("FGT-DC-EDGE")
    );
    // Traffic bytes from CEF in=/out=
    let traffic = event.traffic.expect("CEF in/out bytes -> Traffic");
    assert_eq!(traffic.bytes_in, Some(485401));
    assert_eq!(traffic.bytes_out, Some(1176097));

    // 2. act=deny -> Blocked (action inviolability: never Allowed)
    let sample_deny = "CEF:0|Fortinet|FortiGate|v7.0.2|0000000012|traffic:forward deny|3|src=192.168.6.68 spt=46825 dst=198.51.100.142 dpt=123 proto=17 act=deny cat=traffic:forward app=NTP in=380334 out=2344876 dvchost=FGT-BRANCH-02";
    let event = parser.parse(sample_deny).expect("parse cef deny");
    assert_eq!(event.disposition, disposition::BLOCKED);
    assert_ne!(event.disposition, disposition::ALLOWED);
    assert_eq!(event.connection_info.protocol_num, Some(17));
    assert_eq!(event.connection_info.protocol_name.as_deref(), Some("UDP"));
    assert_eq!(
        event.metadata.raw_hash,
        hex::encode(Sha256::digest(sample_deny.as_bytes()))
    );

    // 3. Session-end states of permitted traffic -> Allowed + CLOSE
    let sample_rst = "CEF:0|Fortinet|FortiGate|v7.0.2|0000000014|traffic:forward server-rst|3|src=192.168.3.14 spt=46909 dst=198.51.100.3 dpt=993 proto=6 act=server-rst cat=traffic:forward app=IMAPS";
    let event = parser.parse(sample_rst).expect("parse cef server-rst");
    assert_eq!(event.disposition, disposition::ALLOWED);
    assert_eq!(event.activity_id, ulpf_core::activity_id::CLOSE);

    let sample_timeout = "CEF:0|Fortinet|FortiGate|v7.0.2|0000000018|traffic:forward timeout|3|src=192.168.3.12 spt=58473 dst=203.0.113.236 dpt=22 proto=6 act=timeout cat=traffic:forward app=SSH";
    let event = parser.parse(sample_timeout).expect("parse cef timeout");
    assert_eq!(event.disposition, disposition::ALLOWED);
    assert_eq!(event.activity_id, ulpf_core::activity_id::CLOSE);

    // 4. act=close -> Allowed + CLOSE (5th distinct fixture)
    let sample_close = "CEF:0|Fortinet|FortiGate|v7.0.2|0000000019|traffic:forward close|3|src=192.168.9.115 spt=34212 dst=203.0.113.50 dpt=80 proto=6 act=close cat=traffic:forward app=HTTP";
    let event = parser.parse(sample_close).expect("parse cef close");
    assert_eq!(event.disposition, disposition::ALLOWED);
    assert_eq!(event.activity_id, ulpf_core::activity_id::CLOSE);

    // 5. Syslog-prefixed CEF from a foreign vendor: vendor from header field 2
    let sample_ms = "<134>Oct 15 10:20:30 gw CEF:0|Microsoft|Windows|10.0.19044|9001|Logon|5|src=10.20.30.40 spt=50122 dst=10.20.30.10 dpt=445 proto=6 act=allowed";
    assert_eq!(parser.classify(sample_ms), VendorFormat::Cef);
    let event = parser.parse(sample_ms).expect("parse syslog-prefixed cef");
    assert_eq!(event.metadata.product.vendor_name, "Microsoft");
    assert_eq!(event.metadata.product.name, "Windows");
    assert_eq!(event.disposition, disposition::ALLOWED);
    assert_eq!(
        event.metadata.raw_hash,
        hex::encode(Sha256::digest(sample_ms.as_bytes()))
    );
}

#[test]
fn test_pfsense_icmp_ports_stay_null() {
    let parser = UniversalParser::new();

    // IPv4 ICMP filterlog: fields after the endpoint IPs are ICMP type-name
    // and code — NOT ports. The extractor must never parse them (the P5 audit
    // caught `Some(0)` here; a numeric ICMP type would fabricate a src_port
    // entirely). Ports are transport-only, and 0 is never emitted (P2
    // normalization, now applied to pfSense too).
    let raw = "Sep 21 14:00:05 pfSense filterlog[20002]: 3,16777216,,1000000588,igb1,match,pass,out,4,0x0,,128,39331,0,none,1,icmp,84,192.168.1.157,8.8.8.8,request,0,0";
    let event = parser.parse(raw).expect("parse pfsense icmp");
    assert_eq!(event.connection_info.protocol_num, Some(1));
    assert_eq!(event.src_endpoint.port, None, "ICMP carries no ports");
    assert_eq!(event.dst_endpoint.port, None, "never Some(0) on ICMP");
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("192.168.1.157"));
    assert_eq!(event.dst_endpoint.ip.as_deref(), Some("8.8.8.8"));

    // numeric ICMP type in the same position must not become a source port
    let raw_t = "Sep 21 14:00:05 pfSense filterlog[20003]: 3,16777216,,1000000589,igb1,match,pass,in,4,0x0,,128,39332,0,none,1,icmp,84,192.168.1.158,8.8.8.8,8,0";
    let event = parser.parse(raw_t).expect("parse pfsense icmp type");
    assert_eq!(
        event.src_endpoint.port, None,
        "ICMP type 8 must not be read as a port"
    );
    assert_eq!(event.dst_endpoint.port, None);

    // TCP/UDP keep their ports (transport protocols have them)
    let raw_tcp = "filterlog: 5,,,1000000103,em0,match,pass,in,4,0x0,,64,12345,0,none,6,tcp,60,192.168.1.50,203.0.113.10,54321,443,0,S,123456,,1024,,";
    let event = parser.parse(raw_tcp).expect("parse pfsense tcp");
    assert_eq!(event.src_endpoint.port, Some(54321));
    assert_eq!(event.dst_endpoint.port, Some(443));
}

// ============================================================================
// P7 — FORMAT EXPANSION: ASA VPN/AAA VERDICTS, PAN THREAT, PFSENSE IPV6
// ============================================================================

/// P7.2 engine half of the shared ASA VPN/AAA verdict vocabulary (the
/// evaluator half lives in `ai_tests::test_p7_gt_tag_refinements...`):
/// success phrases resolve to Allowed, failure phrases to Blocked — even
/// on fallback lines with no `Built`/`Deny`/`Teardown` verb. Lines are
/// deliberately marker-free (one IPv4, no `src=`/`proto=` keys, no
/// transport-name tokens) so the accuracy audit sees null endpoints as
/// correct, never fabricated evidence.
#[test]
fn test_p7_asa_vpn_aaa_verdict_phrases() {
    let parser = UniversalParser::new();

    let aaa_ok = "<130>Sep 21 14:04:11 asa-vpn-gw01 %ASA-6-716059: Group = vpn-users, Username = jdoe, IP = 203.0.113.51, Successful login to server.";
    let ev = parser.parse(aaa_ok).expect("parse AAA success");
    assert_eq!(ev.disposition, disposition::ALLOWED);
    assert!(ev.src_endpoint.ip.is_none() && ev.dst_endpoint.ip.is_none());
    assert!(ev.connection_info.protocol_name.is_none());
    assert_eq!(
        ev.metadata.raw_hash,
        hex::encode(Sha256::digest(aaa_ok.as_bytes()))
    );

    let aaa_fail = "<164>Sep 21 14:04:12 asa-vpn-gw01 %ASA-4-716060: Group = vpn-users, Username = root, IP = 203.0.113.51, authentication failed.";
    let ev = parser.parse(aaa_fail).expect("parse AAA failure");
    assert_eq!(ev.disposition, disposition::BLOCKED);

    let vpn_ok = "<130>Sep 21 14:03:11 asa-vpn-gw01 %ASA-6-713041: Group = vpn-users, IP = 198.51.100.77, IPsec tunnel established.";
    let ev = parser.parse(vpn_ok).expect("parse VPN established");
    assert_eq!(ev.disposition, disposition::ALLOWED);

    // "tunnel" alone must NOT read as established — failure phrase wins.
    let vpn_fail = "<164>Sep 21 14:03:12 asa-vpn-gw01 %ASA-4-713172: Group = vpn-users, IP = 198.51.100.77, IPsec tunnel, authentication failed from gateway.";
    let ev = parser.parse(vpn_fail).expect("parse VPN failure");
    assert_eq!(ev.disposition, disposition::BLOCKED);
    assert_eq!(
        ev.metadata.raw_hash,
        hex::encode(Sha256::digest(vpn_fail.as_bytes()))
    );
}

/// P8 merge rec #1 (counterpart union): a session-disconnect line on a
/// NON-113019 message code falls through to `fallback_parse`, whose verdict
/// vocabulary lacked `session disconnected` — emitting UNKNOWN where the
/// 113019 branch (and now the shared fallback + GT) say Allowed. Mirrors
/// `test_p7_asa_vpn_aaa_verdict_phrases`: engine half; GT half lives in
/// `ai_tests.rs::test_gt_asa_session_disconnected_phrase_lockstep`.
#[test]
fn test_asa_fallback_session_disconnected_phrase() {
    let parser = UniversalParser::new();

    // Non-113019 code (713104) with the disconnect phrase -> Allowed.
    let disc = "<130>Sep 21 14:05:00 asa-vpn-gw01 %ASA-6-713104: Group = vpn-users, IP = 198.51.100.77, Session disconnected.";
    let ev = parser.parse(disc).expect("parse fallback disconnect");
    assert_eq!(
        ev.disposition,
        disposition::ALLOWED,
        "session disconnected (non-113019) must read Allowed, not Unknown"
    );
    assert_eq!(
        ev.metadata.raw_hash,
        hex::encode(Sha256::digest(disc.as_bytes()))
    );

    // Failure phrases still win first: a line carrying both reads Blocked.
    let disc_fail = "<164>Sep 21 14:05:01 asa-vpn-gw01 %ASA-4-716060: Group = vpn-users, IP = 198.51.100.77, Session disconnected after authentication failed.";
    let ev = parser
        .parse(disc_fail)
        .expect("parse fallback disconnect+fail");
    assert_eq!(
        ev.disposition,
        disposition::BLOCKED,
        "failure phrase must outrank the disconnect phrase"
    );
}

/// Full-dataset run finding: `%ASA-4-106007: dropped <proto> from
/// <ip>/<port> to <ip>/<port>, access-list ... denied ...` misses
/// `REGEX_DENIED_CONN` (which needs the literal `... connection denied
/// from ...` phrasing) and fell through to `fallback_parse`, emitting
/// default endpoints/protocol for a line that embeds all five fields —
/// the entire 1,440-record audit dump of the 10,799-line run. Pins
/// endpoints, ports, protocol, DROPPED, byte-exact provenance, and the
/// sibling 106001 shape (must keep flowing through `REGEX_DENIED_CONN`).
#[test]
fn test_asa_106007_dropped_by_access_list_endpoints() {
    let parser = UniversalParser::new();
    let raw = "<164>Sep 21 14:02:16 asa-edge-01 %ASA-4-106007: dropped UDP from 192.0.2.38/36846 to 10.37.135.20/22, access-list outside_in denied icmp 10.37.135.20 -> 192.0.2.38";
    let ev = parser
        .parse(raw)
        .expect("parse ASA 106007 dropped-by-access-list line");
    assert_eq!(ev.src_endpoint.ip.as_deref(), Some("192.0.2.38"));
    assert_eq!(ev.src_endpoint.port, Some(36846));
    assert_eq!(ev.dst_endpoint.ip.as_deref(), Some("10.37.135.20"));
    assert_eq!(ev.dst_endpoint.port, Some(22));
    assert_eq!(ev.connection_info.protocol_name.as_deref(), Some("UDP"));
    assert_eq!(ev.disposition, disposition::DROPPED);
    assert_eq!(
        ev.metadata.raw_hash,
        hex::encode(Sha256::digest(raw.as_bytes()))
    );

    let denied = "<162>Sep 21 14:02:40 asa-dc-01 %ASA-2-106001: Inbound TCP connection denied from 198.51.100.5/5555 to 10.0.0.2/80 flags ACK on interface outside";
    let ev = parser.parse(denied).expect("parse ASA 106001");
    assert_eq!(ev.src_endpoint.ip.as_deref(), Some("198.51.100.5"));
    assert_eq!(ev.src_endpoint.port, Some(5555));
    assert_eq!(ev.dst_endpoint.ip.as_deref(), Some("10.0.0.2"));
    assert_eq!(ev.connection_info.protocol_name.as_deref(), Some("TCP"));
    assert_eq!(ev.disposition, disposition::DROPPED);
}

/// P7.2: PAN-OS THREAT rows parse through the same positional layout as
/// TRAFFIC rows (type token at CSV index 3 anchors `base = 0`; action stays
/// at index 30). Pins endpoints, ports, protocol, deny -> Blocked, and the
/// byte-for-byte lossless contract.
#[test]
fn test_p7_paloalto_threat_csv() {
    let parser = UniversalParser::new();
    let raw = "1,2026/09/21 14:00:07,001801000099,THREAT,end,2304,2026/09/21 14:00:07,10.1.1.5,203.0.113.9,10.1.1.5,203.0.113.9,LAN_to_WAN,acme\\agarcia,,threat-scan,vsys1,LAN,WAN,ethernet1/1,ethernet1/2,default,,100412,1,49152,443,32768,443,0x400000,tcp,deny,512,256,768,4,2026/09/21 14:00:00,21,networking,0,100000155,0x0,192.168.0.0-192.168.255.255,US,0,612,8898,,0,0,0,0,vsys1,PA-5220-FW01,from-policy,,,0,0,0,,N/A,0,0,0,0";
    let event = parser.parse(raw).expect("parse PAN THREAT row");

    assert_eq!(event.metadata.product.vendor_name, "Palo Alto Networks");
    assert_eq!(
        event.disposition,
        disposition::BLOCKED,
        "action col 30 = deny"
    );
    assert_eq!(event.activity_id, activity_id::CLOSE, "subtype = end");
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("10.1.1.5"));
    assert_eq!(event.src_endpoint.port, Some(49152));
    assert_eq!(event.dst_endpoint.ip.as_deref(), Some("203.0.113.9"));
    assert_eq!(event.dst_endpoint.port, Some(443));
    assert_eq!(event.connection_info.protocol_name.as_deref(), Some("TCP"));
    assert_eq!(event.connection_info.protocol_num, Some(6));
    assert_eq!(
        event.metadata.raw_hash,
        hex::encode(Sha256::digest(raw.as_bytes()))
    );
}

/// P7.2: pfSense filterlog IPv6 layout pinned against the official Netgate
/// "Raw Filter Log Format" BNF — after the 9 common fields:
/// `[9]=class [10]=flow-label [11]=hop-limit [12]=proto-text [13]=proto-id
/// [14]=length [15]=src [16]=dst [17]/[18]=ports` (v6 carries TEXT before
/// ID, the reverse of v4). This branch was previously untested.
#[test]
fn test_p7_pfsense_ipv6_row() {
    let parser = UniversalParser::new();
    let raw = "Sep 21 14:00:07 pfSense filterlog[30007]: 1000000103,16777216,,1000000455,igb2,match,pass,in,6,0x0,01a2b,64,tcp,6,1460,2001:db8::5,2001:db8:aaaa::9,51000,443,1400,PA,100001,,65535,,";
    let event = parser.parse(raw).expect("parse pfSense IPv6 row");

    assert_eq!(event.disposition, disposition::ALLOWED);
    assert_eq!(event.activity_id, activity_id::TRAFFIC_FLOW);
    assert_eq!(event.connection_info.protocol_name.as_deref(), Some("TCP"));
    assert_eq!(event.connection_info.protocol_num, Some(6));
    assert_eq!(event.connection_info.direction.as_deref(), Some("Inbound"));
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("2001:db8::5"));
    assert_eq!(event.src_endpoint.port, Some(51000));
    assert_eq!(event.src_endpoint.interface.as_deref(), Some("igb2"));
    assert_eq!(event.dst_endpoint.ip.as_deref(), Some("2001:db8:aaaa::9"));
    assert_eq!(event.dst_endpoint.port, Some(443));
    assert_eq!(
        event
            .unmapped
            .as_ref()
            .and_then(|u| u.get("ip_version"))
            .map(|s| s.as_str()),
        Some("6"),
        "layout discriminator must surface in unmapped"
    );
    assert_eq!(
        event.metadata.raw_hash,
        hex::encode(Sha256::digest(raw.as_bytes()))
    );
}

// ============================================================================
// P11 escape-hardening probes (RED first): CEF backslash escapes and
// PAN-OS quoted-CSV fields. These record what the code does with hostile
// but spec-legal punctuation; the fix follows.
// ============================================================================

#[test]
fn test_cef_escaped_pipe_in_header() {
    let parser = UniversalParser::new();
    // CEF spec: `\|` inside a header field is a literal pipe, not a
    // separator. The name field carries one here.
    let raw = "CEF:0|Fortinet|FortiGate|v7.0.2|0000000019|traffic:forward\\|drop|3|src=192.168.1.146 spt=25297 dst=203.0.113.207 dpt=80 proto=6 act=accept";
    let event = parser.parse(raw).expect("parse cef with escaped pipe");
    let unmapped = event.unmapped.as_ref().expect("unmapped present");
    assert_eq!(
        unmapped.get("cef_name").map(String::as_str),
        Some("traffic:forward|drop"),
        "escaped pipe belongs to the name field"
    );
    assert_eq!(
        unmapped.get("cef_severity").map(String::as_str),
        Some("3"),
        "severity must not shift into the name split"
    );
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("192.168.1.146"));
    assert_eq!(event.disposition, disposition::ALLOWED);
    assert_eq!(
        event.metadata.raw_hash,
        hex::encode(Sha256::digest(raw.as_bytes()))
    );
}

#[test]
fn test_cef_escaped_equals_in_extension() {
    let parser = UniversalParser::new();
    // CEF spec: `\=` is a literal equals inside extension values.
    let raw = "CEF:0|Fortinet|FortiGate|v7.0.2|0000000019|traffic:forward|3|msg=allow\\=yes src=192.168.1.146 spt=25297 dst=203.0.113.207 dpt=80 proto=6 act=accept";
    let event = parser.parse(raw).expect("parse cef with escaped equals");
    let unmapped = event.unmapped.as_ref().expect("unmapped present");
    assert_eq!(
        unmapped.get("msg").map(String::as_str),
        Some("allow=yes"),
        "escaped equals must unescape in the value"
    );
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("192.168.1.146"));
}

#[test]
fn test_multibyte_hostname_line_parses_without_panic() {
    let parser = UniversalParser::new();
    // 5-byte tag + 89 ASCII + '€' (bytes 94-96): the Tier-1 96-byte
    // signature window ends inside the euro sign. Byte slicing there
    // panics ("not a char boundary") — the hot path must not.
    let raw = format!(
        "<166>{}€ %ASA-6-302013: Built inbound TCP connection 1004583 for outside:203.0.113.57/80 to inside:10.1.13.22/80",
        "A".repeat(89)
    );
    // NOTE: `parse_cached` — the plain `parse` bypasses the Tier-1 LRU.
    let event = parser
        .parse_cached(&raw)
        .expect("multibyte prefix must not panic the hot path");
    assert_eq!(event.disposition, disposition::ALLOWED);
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("203.0.113.57"));
    assert_eq!(
        event.metadata.raw_hash,
        hex::encode(Sha256::digest(raw.as_bytes()))
    );
}

#[test]
fn test_paloalto_quoted_csv_with_escaped_quotes() {
    use ulpf_core::parser::extractors::split_csv;

    // Unit contract: RFC-4180 `""` inside a quoted field is one literal
    // quote — it must not toggle the in-quotes state.
    assert_eq!(split_csv("a,\"b,c\",d"), vec!["a", "b,c", "d"]);
    assert_eq!(split_csv("a,\"b\"\"c\",d"), vec!["a", "b\"c", "d"]);

    // End to end: quoted app field with comma + doubled quotes must not
    // shift every column after it (ports/protocol/action stay aligned).
    let parser = UniversalParser::new();
    let raw = "1,2023/10/15 10:20:30,001801000000,TRAFFIC,start,0,2023/10/15 10:20:30,192.168.1.50,203.0.113.25,192.168.1.50,203.0.113.25,allow-web,user1,,\"web, \"\"browsing\"\"\",vsys1,trust,untrust,ethernet1/2,ethernet1/1,log-forwarding,0,12345,1,54321,80,0,0,0x0,tcp,allow,1024,512,512,10,2023/10/15 10:20:30,15,any,0,1234567,0x0";
    let event = parser.parse(raw).expect("parse pan-os quoted csv");
    let unmapped = event.unmapped.as_ref().expect("unmapped present");
    assert_eq!(
        unmapped.get("application").map(String::as_str),
        Some("web, \"browsing\""),
        "quoted field keeps comma + unescaped quotes"
    );
    assert_eq!(event.src_endpoint.port, Some(54321));
    assert_eq!(event.dst_endpoint.port, Some(80));
    assert_eq!(event.disposition, disposition::ALLOWED);
}

// ============================================================================
// P11.2 IPv6 sweep (RED first): every vendor must carry IPv6 endpoints
// exactly. Bare `2001:db8::5/5555` breaks naive first-colon splits
// (interface vs address); these tests pin the correct split.
// ============================================================================

#[test]
fn test_asa_ipv6_denied_endpoints() {
    let parser = UniversalParser::new();
    // 106001 carries BARE ip/port (no interface prefix) — first-colon
    // splitting mangles IPv6 here; the trailing `interface outside`
    // supplies the default interface instead.
    let raw = "%ASA-2-106001: Inbound TCP connection denied from 2001:db8::5/5555 to 2001:db8:1::2/80 flags SYN on interface outside";
    let event = parser.parse(raw).expect("parse asa ipv6 deny");
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("2001:db8::5"));
    assert_eq!(event.src_endpoint.port, Some(5555));
    assert_eq!(
        event.src_endpoint.interface.as_deref(),
        Some("outside"),
        "default interface wins; '2001' is never an interface"
    );
    assert_eq!(event.dst_endpoint.ip.as_deref(), Some("2001:db8:1::2"));
    assert_eq!(event.dst_endpoint.port, Some(80));
    assert_eq!(event.disposition, disposition::DROPPED);
    assert_eq!(
        event.metadata.raw_hash,
        hex::encode(Sha256::digest(raw.as_bytes()))
    );
}

#[test]
fn test_asa_bracketed_ipv6_endpoints() {
    let parser = UniversalParser::new();
    // Bracketed forms: `outside:[2001:db8::57]/80` (built) and bare
    // `[2001:db8::5]/5555` (106001). Edge-trim eats the opening bracket
    // before the port split, so the hostpart must shed brackets itself —
    // otherwise the IP check fails and `2001` becomes an interface.
    let raw = "%ASA-6-302013: Built inbound TCP connection 1004583 for outside:[2001:db8::57]/80 to inside:[2001:db8:1::9]/443";
    let event = parser.parse(raw).expect("parse asa bracketed ipv6");
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("2001:db8::57"));
    assert_eq!(event.src_endpoint.port, Some(80));
    assert_eq!(event.src_endpoint.interface.as_deref(), Some("outside"));
    assert_eq!(event.dst_endpoint.ip.as_deref(), Some("2001:db8:1::9"));
    assert_eq!(event.dst_endpoint.port, Some(443));

    let raw2 = "%ASA-2-106001: Inbound TCP connection denied from [2001:db8::5]/5555 to [2001:db8:1::2]/80 flags SYN on interface outside";
    let event2 = parser.parse(raw2).expect("parse asa bare bracketed ipv6");
    assert_eq!(event2.src_endpoint.ip.as_deref(), Some("2001:db8::5"));
    assert_eq!(event2.src_endpoint.port, Some(5555));
    assert_eq!(event2.src_endpoint.interface.as_deref(), Some("outside"));
    assert_eq!(event2.dst_endpoint.ip.as_deref(), Some("2001:db8:1::2"));
    assert_eq!(
        event2.metadata.raw_hash,
        hex::encode(Sha256::digest(raw2.as_bytes()))
    );
}

#[test]
fn test_fortigate_ipv6_endpoints() {
    let parser = UniversalParser::new();
    let raw = "date=2023-10-15 time=10:20:30 devname=\"FGT60D\" logid=\"0000000013\" type=\"traffic\" srcip=2001:db8::5 srcport=51234 dstip=2001:db8:1::9 dstport=443 proto=6 action=accept policyid=1";
    let event = parser.parse(raw).expect("parse fortigate ipv6");
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("2001:db8::5"));
    assert_eq!(event.src_endpoint.port, Some(51234));
    assert_eq!(event.dst_endpoint.ip.as_deref(), Some("2001:db8:1::9"));
    assert_eq!(event.dst_endpoint.port, Some(443));
    assert_eq!(event.disposition, disposition::ALLOWED);
    assert_eq!(
        event.metadata.raw_hash,
        hex::encode(Sha256::digest(raw.as_bytes()))
    );
}

#[test]
fn test_paloalto_ipv6_endpoints() {
    let parser = UniversalParser::new();
    let raw = "1,2023/10/15 10:20:30,001801000000,TRAFFIC,start,0,2023/10/15 10:20:30,2001:db8::50,2001:db8:2::25,2001:db8::50,2001:db8:2::25,allow-web,user1,,web-browsing,vsys1,trust,untrust,ethernet1/2,ethernet1/1,log-forwarding,0,12345,1,54321,443,0,0,0x0,tcp,allow,1024,512,512,10,2023/10/15 10:20:30,15,any,0,1234567,0x0";
    let event = parser.parse(raw).expect("parse pan-os ipv6");
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("2001:db8::50"));
    assert_eq!(event.src_endpoint.port, Some(54321));
    assert_eq!(event.dst_endpoint.ip.as_deref(), Some("2001:db8:2::25"));
    assert_eq!(event.dst_endpoint.port, Some(443));
    assert_eq!(event.disposition, disposition::ALLOWED);
    assert_eq!(
        event.metadata.raw_hash,
        hex::encode(Sha256::digest(raw.as_bytes()))
    );
}

#[test]
fn test_cef_ipv6_endpoints() {
    let parser = UniversalParser::new();
    let raw = "CEF:0|Fortinet|FortiGate|v7.0.2|0000000019|traffic:forward accept|3|src=2001:db8::5 spt=25297 dst=2001:db8:1::9 dpt=443 proto=6 act=accept";
    let event = parser.parse(raw).expect("parse cef ipv6");
    assert_eq!(event.src_endpoint.ip.as_deref(), Some("2001:db8::5"));
    assert_eq!(event.src_endpoint.port, Some(25297));
    assert_eq!(event.dst_endpoint.ip.as_deref(), Some("2001:db8:1::9"));
    assert_eq!(event.dst_endpoint.port, Some(443));
    assert_eq!(event.disposition, disposition::ALLOWED);
    assert_eq!(
        event.metadata.raw_hash,
        hex::encode(Sha256::digest(raw.as_bytes()))
    );
}
