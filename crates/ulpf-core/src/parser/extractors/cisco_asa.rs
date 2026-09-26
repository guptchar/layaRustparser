use chrono::Utc;
use regex::Regex;
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::OnceLock;

use super::protocol_num_from_name;
use crate::schema::ocsf::{
    activity_id, disposition, ConnectionInfo, Endpoint, Metadata, NetworkActivity, Product, Traffic,
};

static REGEX_ASA_HEADER: OnceLock<Regex> = OnceLock::new();
static REGEX_BUILT: OnceLock<Regex> = OnceLock::new();
static REGEX_TEARDOWN: OnceLock<Regex> = OnceLock::new();
static REGEX_DENY: OnceLock<Regex> = OnceLock::new();
static REGEX_DENIED_CONN: OnceLock<Regex> = OnceLock::new();
static REGEX_DROPPED_ACL: OnceLock<Regex> = OnceLock::new();
static REGEX_SESSION_DISCONNECT: OnceLock<Regex> = OnceLock::new();

pub struct CiscoAsaExtractor;

impl CiscoAsaExtractor {
    pub fn new() -> Self {
        // Pre-compile regexes once
        REGEX_ASA_HEADER.get_or_init(|| {
            Regex::new(r"%ASA-(\d+)-(\d+):\s*(.*)").expect("Invalid ASA header regex")
        });
        REGEX_BUILT.get_or_init(|| {
            Regex::new(r"Built\s+(inbound|outbound)?\s*([A-Za-z0-9]+)\s+connection\s+(\d+)\s+for\s+([^\s]+)(?:\s+\([^\)]+\))?\s+to\s+([^\s]+)")
                .expect("Invalid ASA built regex")
        });
        REGEX_TEARDOWN.get_or_init(|| {
            Regex::new(r"Teardown\s+([A-Za-z0-9]+)\s+connection\s+(\d+)\s+for\s+([^\s]+)\s+to\s+([^\s]+)(?:.*?duration\s+([^\s]+))?(?:.*?bytes\s+(\d+))?")
                .expect("Invalid ASA teardown regex")
        });
        REGEX_DENY.get_or_init(|| {
            Regex::new(r"Deny\s+([A-Za-z0-9]+)\s+src\s+([^\s]+)\s+dst\s+([^\s]+)(?:.*?by\s+access-group\s+([^\s\[]+))?")
                .expect("Invalid ASA deny regex")
        });
        REGEX_DENIED_CONN.get_or_init(|| {
            Regex::new(r"(?:(Inbound|Outbound)\s+)?([A-Za-z0-9]+)\s+connection\s+denied\s+from\s+([^\s]+)\s+to\s+([^\s]+)(?:.*?interface\s+([^\s]+))?")
                .expect("Invalid ASA drop regex")
        });
        REGEX_DROPPED_ACL.get_or_init(|| {
            // %ASA-4-106007 dropped-by-access-list shape: "dropped <proto>
            // from <ip>/<port> to <ip>/<port>, access-list ... denied ..." —
            // no "... connection denied ..." phrase, so REGEX_DENIED_CONN
            // misses it. Trailing comma excluded from the dst endpoint
            // (`[^\s,]+`) or `u16` port parsing would fail.
            Regex::new(r"(?i)dropped\s+([A-Za-z0-9]+)\s+from\s+([^\s,]+)\s+to\s+([^\s,]+)")
                .expect("Invalid ASA dropped-by-access-list regex")
        });
        REGEX_SESSION_DISCONNECT.get_or_init(|| {
            Regex::new(r"Group\s*=\s*([^,]+),\s*Username\s*=\s*([^,]+),\s*IP\s*=\s*([^,\s]+),\s*Session disconnected\.\s*Session Type:\s*([^,]+),\s*Duration:\s*([^,]+),\s*Bytes xmt:\s*(\d+),\s*Bytes rcv:\s*(\d+),\s*Reason:\s*(.+?)\s*$")
                .expect("Invalid ASA session disconnect regex")
        });

        Self
    }

    pub fn parse(&self, raw: &str) -> anyhow::Result<NetworkActivity> {
        let header_re = REGEX_ASA_HEADER.get().unwrap();
        let captures = header_re.captures(raw).ok_or_else(|| {
            anyhow::anyhow!("Raw log does not contain valid %ASA- header: {}", raw)
        })?;

        let severity: u8 = captures
            .get(1)
            .map_or(6, |m| m.as_str().parse().unwrap_or(6));
        let message_code = captures.get(2).map_or("", |m| m.as_str());
        let body = captures.get(3).map_or("", |m| m.as_str());

        let mut unmapped = HashMap::new();
        unmapped.insert("cisco_severity".to_string(), severity.to_string());
        unmapped.insert("cisco_message_code".to_string(), message_code.to_string());

        let now_ms = Utc::now().timestamp_millis();

        match message_code {
            // Built connection: %ASA-6-302013 or similar built events (302015, 302020)
            "302013" | "302015" | "302020" => {
                let built_re = REGEX_BUILT.get().unwrap();
                if let Some(caps) = built_re.captures(body) {
                    let dir_str = caps.get(1).map(|m| m.as_str()).unwrap_or("Unknown");
                    let proto_str = caps.get(2).map(|m| m.as_str()).unwrap_or("TCP");
                    let conn_id = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                    let src_str = caps.get(4).map(|m| m.as_str()).unwrap_or("");
                    let dst_str = caps.get(5).map(|m| m.as_str()).unwrap_or("");

                    let (src_ip, src_port, src_intf) = parse_endpoint_str(src_str, None);
                    let (dst_ip, dst_port, dst_intf) = parse_endpoint_str(dst_str, None);

                    let proto_name = proto_str.to_ascii_uppercase();
                    let proto_num = protocol_num_from_name(&proto_name);
                    let direction = normalize_direction(dir_str);

                    unmapped.insert("connection_id".to_string(), conn_id.to_string());

                    let src_endpoint = Endpoint::new(src_ip, src_port, src_intf, None);
                    let dst_endpoint = Endpoint::new(dst_ip, dst_port, dst_intf, None);
                    let connection_info =
                        ConnectionInfo::new(proto_num, Some(proto_name), Some(direction));

                    let product = Product::new("Cisco", "ASA", None);
                    let metadata = Metadata::new(product, raw, "", "", now_ms);

                    Ok(NetworkActivity::new(
                        activity_id::OPEN,
                        now_ms,
                        disposition::ALLOWED,
                        src_endpoint,
                        dst_endpoint,
                        connection_info,
                        None,
                        metadata,
                    )
                    .with_unmapped(unmapped))
                } else {
                    self.fallback_parse(raw, message_code, body, now_ms, unmapped)
                }
            }

            // Teardown connection: %ASA-6-302014 or similar teardowns (302016, 302021)
            "302014" | "302016" | "302021" => {
                let teardown_re = REGEX_TEARDOWN.get().unwrap();
                if let Some(caps) = teardown_re.captures(body) {
                    let proto_str = caps.get(1).map(|m| m.as_str()).unwrap_or("TCP");
                    let conn_id = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let src_str = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                    let dst_str = caps.get(4).map(|m| m.as_str()).unwrap_or("");
                    let duration = caps.get(5).map(|m| m.as_str());
                    let bytes = caps.get(6).and_then(|m| m.as_str().parse::<u64>().ok());

                    let (src_ip, src_port, src_intf) = parse_endpoint_str(src_str, None);
                    let (dst_ip, dst_port, dst_intf) = parse_endpoint_str(dst_str, None);

                    let proto_name = proto_str.to_ascii_uppercase();
                    let proto_num = protocol_num_from_name(&proto_name);

                    unmapped.insert("connection_id".to_string(), conn_id.to_string());
                    if let Some(d) = duration {
                        unmapped.insert("duration".to_string(), d.to_string());
                    }

                    let traffic = bytes.map(|b| Traffic::new(None, Some(b), None, None));

                    let src_endpoint = Endpoint::new(src_ip, src_port, src_intf, None);
                    let dst_endpoint = Endpoint::new(dst_ip, dst_port, dst_intf, None);
                    let connection_info = ConnectionInfo::new(proto_num, Some(proto_name), None);

                    let product = Product::new("Cisco", "ASA", None);
                    let metadata = Metadata::new(product, raw, "", "", now_ms);

                    Ok(NetworkActivity::new(
                        activity_id::CLOSE,
                        now_ms,
                        disposition::ALLOWED,
                        src_endpoint,
                        dst_endpoint,
                        connection_info,
                        traffic,
                        metadata,
                    )
                    .with_unmapped(unmapped))
                } else {
                    self.fallback_parse(raw, message_code, body, now_ms, unmapped)
                }
            }

            // Deny packet / access-group: %ASA-4-106023
            "106023" => {
                let deny_re = REGEX_DENY.get().unwrap();
                if let Some(caps) = deny_re.captures(body) {
                    let proto_str = caps.get(1).map(|m| m.as_str()).unwrap_or("TCP");
                    let src_str = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let dst_str = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                    let acl = caps.get(4).map(|m| m.as_str().trim_matches('"'));

                    let (src_ip, src_port, src_intf) = parse_endpoint_str(src_str, None);
                    let (dst_ip, dst_port, dst_intf) = parse_endpoint_str(dst_str, None);

                    let proto_name = proto_str.to_ascii_uppercase();
                    let proto_num = protocol_num_from_name(&proto_name);

                    if let Some(a) = acl {
                        unmapped.insert("access_group".to_string(), a.to_string());
                    }

                    let src_endpoint = Endpoint::new(src_ip, src_port, src_intf, None);
                    let dst_endpoint = Endpoint::new(dst_ip, dst_port, dst_intf, None);
                    let connection_info = ConnectionInfo::new(proto_num, Some(proto_name), None);

                    let product = Product::new("Cisco", "ASA", None);
                    let metadata = Metadata::new(product, raw, "", "", now_ms);

                    Ok(NetworkActivity::new(
                        activity_id::OTHER,
                        now_ms,
                        disposition::BLOCKED,
                        src_endpoint,
                        dst_endpoint,
                        connection_info,
                        None,
                        metadata,
                    )
                    .with_unmapped(unmapped))
                } else {
                    self.fallback_parse(raw, message_code, body, now_ms, unmapped)
                }
            }

            // Drop / Inbound connection denied: %ASA-2-106001
            "106001" | "106006" | "106007" => {
                let drop_re = REGEX_DENIED_CONN.get().unwrap();
                if let Some(caps) = drop_re.captures(body) {
                    let dir_str = caps.get(1).map(|m| m.as_str()).unwrap_or("Inbound");
                    let proto_str = caps.get(2).map(|m| m.as_str()).unwrap_or("TCP");
                    let src_str = caps.get(3).map(|m| m.as_str()).unwrap_or("");
                    let dst_str = caps.get(4).map(|m| m.as_str()).unwrap_or("");
                    let intf_str = caps.get(5).map(|m| m.as_str());

                    let (src_ip, src_port, src_intf) = parse_endpoint_str(src_str, intf_str);
                    let (dst_ip, dst_port, dst_intf) = parse_endpoint_str(dst_str, None);

                    let proto_name = proto_str.to_ascii_uppercase();
                    let proto_num = protocol_num_from_name(&proto_name);
                    let direction = normalize_direction(dir_str);

                    let src_endpoint = Endpoint::new(src_ip, src_port, src_intf, None);
                    let dst_endpoint = Endpoint::new(dst_ip, dst_port, dst_intf, None);
                    let connection_info =
                        ConnectionInfo::new(proto_num, Some(proto_name), Some(direction));

                    let product = Product::new("Cisco", "ASA", None);
                    let metadata = Metadata::new(product, raw, "", "", now_ms);

                    Ok(NetworkActivity::new(
                        activity_id::OTHER,
                        now_ms,
                        disposition::DROPPED,
                        src_endpoint,
                        dst_endpoint,
                        connection_info,
                        None,
                        metadata,
                    )
                    .with_unmapped(unmapped))
                } else if let Some(caps) = REGEX_DROPPED_ACL.get().unwrap().captures(body) {
                    // 106007 dropped shape — extract the five embedded
                    // fields instead of falling through to default
                    // endpoints. No direction word exists in this raw:
                    // emit None (honest, never fabricated "Inbound").
                    let proto_str = caps.get(1).map(|m| m.as_str()).unwrap_or("UDP");
                    let src_str = caps.get(2).map(|m| m.as_str()).unwrap_or("");
                    let dst_str = caps.get(3).map(|m| m.as_str()).unwrap_or("");

                    let (src_ip, src_port, src_intf) = parse_endpoint_str(src_str, None);
                    let (dst_ip, dst_port, dst_intf) = parse_endpoint_str(dst_str, None);

                    let proto_name = proto_str.to_ascii_uppercase();
                    let proto_num = protocol_num_from_name(&proto_name);

                    let src_endpoint = Endpoint::new(src_ip, src_port, src_intf, None);
                    let dst_endpoint = Endpoint::new(dst_ip, dst_port, dst_intf, None);
                    let connection_info = ConnectionInfo::new(proto_num, Some(proto_name), None);

                    let product = Product::new("Cisco", "ASA", None);
                    let metadata = Metadata::new(product, raw, "", "", now_ms);

                    Ok(NetworkActivity::new(
                        activity_id::OTHER,
                        now_ms,
                        disposition::DROPPED,
                        src_endpoint,
                        dst_endpoint,
                        connection_info,
                        None,
                        metadata,
                    )
                    .with_unmapped(unmapped))
                } else {
                    self.fallback_parse(raw, message_code, body, now_ms, unmapped)
                }
            }

            // VPN session disconnect: %ASA-4-113019. No ports/protocol exist in the
            // raw line — emit None (honest nulls, never fabricated values); a normal
            // session end of permitted traffic is Allowed + CLOSE (OCSF).
            "113019" => {
                let disc_re = REGEX_SESSION_DISCONNECT.get().unwrap();
                if let Some(caps) = disc_re.captures(body) {
                    let group = caps.get(1).map(|m| m.as_str().trim());
                    let username = caps.get(2).map(|m| m.as_str().trim());
                    let peer_ip = caps.get(3).map(|m| m.as_str().trim());
                    let session_type = caps.get(4).map(|m| m.as_str().trim());
                    let duration = caps.get(5).map(|m| m.as_str().trim());
                    let bytes_xmt = caps.get(6).and_then(|m| m.as_str().parse::<u64>().ok());
                    let bytes_rcv = caps.get(7).and_then(|m| m.as_str().parse::<u64>().ok());
                    let reason = caps.get(8).map(|m| m.as_str().trim());

                    if let Some(g) = group {
                        unmapped.insert("vpn_group".to_string(), g.to_string());
                    }
                    if let Some(u) = username {
                        unmapped.insert("username".to_string(), u.to_string());
                    }
                    if let Some(s) = session_type {
                        unmapped.insert("session_type".to_string(), s.to_string());
                    }
                    if let Some(d) = duration {
                        unmapped.insert("duration".to_string(), d.to_string());
                    }
                    if let Some(r) = reason {
                        unmapped.insert("disconnect_reason".to_string(), r.to_string());
                    }

                    let traffic = match (bytes_rcv, bytes_xmt) {
                        (Some(rcv), Some(xmt)) => {
                            Some(Traffic::new(Some(rcv), Some(xmt), None, None))
                        }
                        _ => None,
                    };

                    let src_endpoint =
                        Endpoint::new(peer_ip.map(|s| s.to_string()), None, None, None);
                    let product = Product::new("Cisco", "ASA", None);
                    let metadata = Metadata::new(product, raw, "", "", now_ms);

                    Ok(NetworkActivity::new(
                        activity_id::CLOSE,
                        now_ms,
                        disposition::ALLOWED,
                        src_endpoint,
                        Endpoint::default(),
                        ConnectionInfo::default(),
                        traffic,
                        metadata,
                    )
                    .with_unmapped(unmapped))
                } else {
                    self.fallback_parse(raw, message_code, body, now_ms, unmapped)
                }
            }

            // Other ASA message codes
            _ => self.fallback_parse(raw, message_code, body, now_ms, unmapped),
        }
    }

    fn fallback_parse(
        &self,
        raw: &str,
        _message_code: &str,
        body: &str,
        now_ms: i64,
        unmapped: HashMap<String, String>,
    ) -> anyhow::Result<NetworkActivity> {
        // P7.2 shared verdict vocabulary — the evaluator's
        // `extract_ground_truth` mirrors this list on the GT side; keep BOTH
        // in lockstep. VPN/AAA fallback lines carry no Built/Deny/Teardown
        // verb, so phrase evidence decides: failure phrases win first (a
        // line can mention both a tunnel and a failed authentication),
        // then success phrases, then the historical verb ladder.
        let body_lower = body.to_ascii_lowercase();
        let disp = if body_lower.contains("authentication failed")
            || body_lower.contains("login failed")
        {
            disposition::BLOCKED
        } else if body.contains("Built")
            || body.contains("Teardown")
            || body_lower.contains("successful login")
            || body_lower.contains("tunnel established")
            // P8 merge rec #1 (counterpart union): a disconnect on a
            // non-113019 code is a normal end of permitted traffic -> Allowed
            // (OCSF), matching the 113019 branch. After the failure phrases
            // so a line carrying both still reads Blocked.
            || body_lower.contains("session disconnected")
        {
            disposition::ALLOWED
        } else if body.contains("Deny") || body.contains("denied") {
            disposition::BLOCKED
        } else if body.contains("drop") || body.contains("dropped") {
            disposition::DROPPED
        } else {
            disposition::UNKNOWN
        };

        let act_id = if body.contains("Built") {
            activity_id::OPEN
        } else if body.contains("Teardown") {
            activity_id::CLOSE
        } else {
            activity_id::OTHER
        };

        let product = Product::new("Cisco", "ASA", None);
        let metadata = Metadata::new(product, raw, "", "", now_ms);

        Ok(NetworkActivity::new(
            act_id,
            now_ms,
            disp,
            Endpoint::default(),
            Endpoint::default(),
            ConnectionInfo::default(),
            None,
            metadata,
        )
        .with_unmapped(unmapped))
    }
}

impl Default for CiscoAsaExtractor {
    fn default() -> Self {
        Self::new()
    }
}

fn normalize_direction(dir: &str) -> String {
    match dir.to_ascii_lowercase().as_str() {
        "inbound" | "in" => "Inbound".to_string(),
        "outbound" | "out" => "Outbound".to_string(),
        _ => "Unknown".to_string(),
    }
}

/// Parses an endpoint string of the form "interface:ip/port", "ip/port",
/// "interface:ip", "ip", "[v6]/port" or "interface:[v6]/port".
///
/// Colon disambiguation: the port splits off the LAST '/' first (slashes
/// never occur in IPs). What remains is an interface prefix only if it is
/// NOT itself an IP literal — `2001:db8::1` parses as an address, so a
/// bare IPv6 endpoint keeps `default_intf` instead of gaining a
/// bogus interface like "2001". Single-colon `name:v4` keeps the old
/// first-colon split (unchanged fast path for IPv4 lines).
fn parse_endpoint_str(
    text: &str,
    default_intf: Option<&str>,
) -> (Option<String>, Option<u16>, Option<String>) {
    let clean = text
        .trim()
        .trim_matches(|c: char| c == '(' || c == ')' || c == '[' || c == ']');

    let (hostpart, port) = match clean.rsplit_once('/') {
        Some((h, p)) => (h, p.parse::<u16>().ok()),
        None => (clean, None),
    };

    // Brackets never occur in interface names or IPs: syslog `[v6]`
    // wrapping (and the lone trailing `]` left when edge-trim ate the
    // opening bracket before this split) must go before the IP check,
    // or `[2001:db8::5]` fails it and `2001` becomes an interface.
    // Gated on presence: clean lines keep borrowing, allocate nothing.
    let hostpart: Cow<str> = if hostpart.contains(['[', ']']) {
        Cow::Owned(hostpart.replace(['[', ']'], ""))
    } else {
        Cow::Borrowed(hostpart)
    };
    let hostpart = hostpart.as_ref();

    if hostpart.contains(':') && hostpart.parse::<std::net::IpAddr>().is_ok() {
        // Bare IP literal (v4-mapped or IPv6): no interface prefix.
        (
            Some(hostpart.to_string()),
            port,
            default_intf.map(|s| s.to_string()),
        )
    } else if let Some(colon_pos) = hostpart.find(':') {
        let (i, r) = hostpart.split_at(colon_pos);
        (Some(r[1..].to_string()), port, Some(i.to_string()))
    } else {
        (
            Some(hostpart.to_string()),
            port,
            default_intf.map(|s| s.to_string()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cisco_asa_built() {
        let extractor = CiscoAsaExtractor::new();
        let raw = "%ASA-6-302013: Built inbound UDP connection 12345 for outside:192.168.1.50/51234 (192.168.1.50/51234) to inside:10.0.0.1/53 (10.0.0.1/53)";
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.activity_id, activity_id::OPEN);
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
    }

    #[test]
    fn test_cisco_asa_teardown() {
        let extractor = CiscoAsaExtractor::new();
        let raw = "%ASA-6-302014: Teardown TCP connection 98765 for inside:10.0.0.5/49152 to outside:203.0.113.10/443 duration 0:00:30 bytes 1234 TCP FINs";
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.activity_id, activity_id::CLOSE);
        assert_eq!(event.disposition, disposition::ALLOWED);
        assert_eq!(event.src_endpoint.ip.as_deref(), Some("10.0.0.5"));
        assert_eq!(event.src_endpoint.port, Some(49152));
        assert_eq!(event.dst_endpoint.ip.as_deref(), Some("203.0.113.10"));
        assert_eq!(event.dst_endpoint.port, Some(443));
        assert_eq!(event.traffic.as_ref().and_then(|t| t.bytes_out), Some(1234));
    }

    #[test]
    fn test_cisco_asa_deny() {
        let extractor = CiscoAsaExtractor::new();
        let raw = "%ASA-4-106023: Deny tcp src outside:198.51.100.25/1234 dst inside:10.0.0.10/80 by access-group \"outside_in\" [0x0, 0x0]";
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.activity_id, activity_id::OTHER);
        assert_eq!(event.disposition, disposition::BLOCKED);
        assert_eq!(event.src_endpoint.ip.as_deref(), Some("198.51.100.25"));
        assert_eq!(event.src_endpoint.port, Some(1234));
        assert_eq!(event.dst_endpoint.ip.as_deref(), Some("10.0.0.10"));
        assert_eq!(event.dst_endpoint.port, Some(80));
    }

    #[test]
    fn test_cisco_asa_drop() {
        let extractor = CiscoAsaExtractor::new();
        let raw = "%ASA-2-106001: Inbound TCP connection denied from 198.51.100.5/5555 to 10.0.0.2/80 flags SYN on interface outside";
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.activity_id, activity_id::OTHER);
        assert_eq!(event.disposition, disposition::DROPPED);
        assert_eq!(event.src_endpoint.ip.as_deref(), Some("198.51.100.5"));
        assert_eq!(event.src_endpoint.port, Some(5555));
        assert_eq!(event.src_endpoint.interface.as_deref(), Some("outside"));
        assert_eq!(event.dst_endpoint.ip.as_deref(), Some("10.0.0.2"));
        assert_eq!(event.dst_endpoint.port, Some(80));
    }

    #[test]
    fn test_cisco_asa_session_disconnect_113019() {
        let extractor = CiscoAsaExtractor::new();
        let raw = "<164>Sep 21 14:00:12 asa-dc-01 %ASA-4-113019: Group = RemoteAccess-Corp, Username = agarcia, IP = 203.0.113.163, Session disconnected. Session Type: SSL, Duration: 0h:39m:20s, Bytes xmt: 32799774, Bytes rcv: 663531, Reason: User Requested";
        let event = extractor.parse(raw).unwrap();

        assert_eq!(event.activity_id, activity_id::CLOSE);
        assert_eq!(event.disposition, disposition::ALLOWED);
        assert_eq!(
            event.src_endpoint.ip.as_deref(),
            Some("203.0.113.163"),
            "VPN peer IP is the session endpoint"
        );
        // No ports or protocol exist in this message — honest nulls
        assert_eq!(event.src_endpoint.port, None);
        assert_eq!(event.dst_endpoint.ip, None);
        assert_eq!(event.connection_info.protocol_name, None);
        assert_eq!(event.connection_info.protocol_num, None);
        assert_eq!(
            event.traffic.as_ref().and_then(|t| t.bytes_out),
            Some(32799774)
        );
        assert_eq!(
            event.traffic.as_ref().and_then(|t| t.bytes_in),
            Some(663531)
        );
        let unmapped = event.unmapped.unwrap();
        assert_eq!(
            unmapped.get("username").map(|s| s.as_str()),
            Some("agarcia")
        );
        assert_eq!(
            unmapped.get("disconnect_reason").map(|s| s.as_str()),
            Some("User Requested")
        );
        assert_eq!(
            unmapped.get("vpn_group").map(|s| s.as_str()),
            Some("RemoteAccess-Corp")
        );
    }
}
