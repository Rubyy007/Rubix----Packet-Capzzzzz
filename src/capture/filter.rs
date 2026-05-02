// src/capture/filter.rs
//! BPF filter builder for RUBIX
//! Constructs libpcap BPF filter expressions from policy rules.
//! Used by both LinuxCapture and WindowsCapture.

/// Builds a BPF filter string from a list of IPs and ports to block.
///
/// The resulting filter is applied at the kernel level (via libpcap/Npcap)
/// so blocked traffic never even reaches userspace — zero cost in the fast path.
///
/// # Example
/// ```
/// let filter = FilterBuilder::new()
///     .block_ips(&["185.230.125.100", "94.102.61.78"])
///     .block_ports(&[445, 3389])
///     .allow_protocols(&["tcp", "udp"])
///     .build();
/// // → "(ip or ip6) and not (host 185.230.125.100 or host 94.102.61.78) and not (port 445 or port 3389)"
/// ```
#[derive(Debug, Default)]
pub struct FilterBuilder {
    block_ips: Vec<String>,
    block_ports: Vec<u16>,
    allow_protocols: Vec<String>,
    custom: Option<String>,
}

impl FilterBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Block traffic to/from these IPs at the kernel level
    pub fn block_ips(mut self, ips: &[&str]) -> Self {
        self.block_ips = ips.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Block traffic on these ports at the kernel level
    pub fn block_ports(mut self, ports: &[u16]) -> Self {
        self.block_ports = ports.to_vec();
        self
    }

    /// Only capture these protocols (e.g. "tcp", "udp", "icmp")
    /// If empty, captures all IP/IPv6 traffic.
    pub fn allow_protocols(mut self, protocols: &[&str]) -> Self {
        self.allow_protocols = protocols.iter().map(|s| s.to_string()).collect();
        self
    }

    /// Override everything with a raw BPF expression.
    /// Use this when the config file provides a custom filter.
    pub fn custom(mut self, expr: &str) -> Self {
        self.custom = Some(expr.to_string());
        self
    }

    /// Build the final BPF filter string.
    /// Returns None if no filters are set (capture everything).
    pub fn build(self) -> Option<String> {
        // Custom expression overrides everything
        if let Some(expr) = self.custom {
            return Some(expr);
        }

        let mut parts: Vec<String> = Vec::new();

        // Protocol filter — always capture IP/IPv6 unless overridden
        if self.allow_protocols.is_empty() {
            parts.push("(ip or ip6)".to_string());
        } else {
            let proto_expr = self.allow_protocols.join(" or ");
            parts.push(format!("({})", proto_expr));
        }

        // IP block filter: "not (host A or host B)"
        if !self.block_ips.is_empty() {
            let ip_expr = self.block_ips
                .iter()
                .map(|ip| format!("host {}", ip))
                .collect::<Vec<_>>()
                .join(" or ");
            parts.push(format!("not ({})", ip_expr));
        }

        // Port block filter: "not (port 445 or port 3389)"
        if !self.block_ports.is_empty() {
            let port_expr = self.block_ports
                .iter()
                .map(|p| format!("port {}", p))
                .collect::<Vec<_>>()
                .join(" or ");
            parts.push(format!("not ({})", port_expr));
        }

        if parts.is_empty() {
            None
        } else {
            Some(parts.join(" and "))
        }
    }

    /// Build a simple default filter — captures all IP/IPv6 traffic.
    /// The policy engine handles decisions in userspace.
    pub fn default_filter() -> String {
        "ip or ip6".to_string()
    }

    /// Build a kernel-level pre-filter from known bad IPs and ports.
    ///
    /// These are dropped by Npcap/libpcap before being copied to userspace —
    /// zero cost in the fast path since the kernel handles the drop.
    pub fn from_block_list(ips: &[String], ports: &[u16]) -> Option<String> {
        let ip_refs: Vec<&str> = ips.iter().map(|s| s.as_str()).collect();
        FilterBuilder::new()
            .block_ips(&ip_refs)
            .block_ports(ports)
            .build()
    }
}

/// Validate a BPF filter expression by attempting to compile it.
///
/// On Windows, pcap_open_dead does not support filter compilation via Npcap,
/// so validation is skipped — invalid filters will fail at capture open time
/// with a clear error message instead.
///
/// On Linux, validation uses a dead capture handle which is fully supported.
pub fn validate_filter(expr: &str) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    {
        // Npcap does not support filter validation on dead handles.
        // Skip here — the filter will be validated when the real capture opens.
        let _ = expr;
        return Ok(());
    }

    #[cfg(not(target_os = "windows"))]
    {
        match pcap::Capture::dead(pcap::Linktype::ETHERNET) {
            Ok(mut cap) => cap
                .filter(expr, true)
                .map_err(|e| format!("Invalid BPF filter '{}': {}", expr, e)),
            Err(e) => Err(format!("Could not create validation handle: {}", e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_filter() {
        let f = FilterBuilder::new().build();
        assert_eq!(f, Some("(ip or ip6)".to_string()));
    }

    #[test]
    fn test_ip_block_filter() {
        let f = FilterBuilder::new()
            .block_ips(&["1.2.3.4", "5.6.7.8"])
            .build()
            .unwrap();
        assert!(f.contains("host 1.2.3.4"));
        assert!(f.contains("host 5.6.7.8"));
        assert!(f.contains("not"));
    }

    #[test]
    fn test_port_block_filter() {
        let f = FilterBuilder::new()
            .block_ports(&[445, 3389])
            .build()
            .unwrap();
        assert!(f.contains("port 445"));
        assert!(f.contains("port 3389"));
        assert!(f.contains("not"));
    }

    #[test]
    fn test_custom_overrides_everything() {
        let f = FilterBuilder::new()
            .block_ips(&["1.2.3.4"])
            .custom("tcp port 80")
            .build()
            .unwrap();
        assert_eq!(f, "tcp port 80");
    }

    #[test]
    fn test_combined_filter() {
        let f = FilterBuilder::new()
            .block_ips(&["185.230.125.100"])
            .block_ports(&[445])
            .build()
            .unwrap();
        assert!(f.contains("ip or ip6"));
        assert!(f.contains("host 185.230.125.100"));
        assert!(f.contains("port 445"));
    }

    #[test]
    fn test_from_block_list_empty() {
        // Empty block list should still produce a base filter
        let f = FilterBuilder::from_block_list(&[], &[]);
        assert_eq!(f, Some("(ip or ip6)".to_string()));
    }

    #[test]
    fn test_from_block_list_with_ips() {
        let ips = vec![
            "185.230.125.100".to_string(),
            "94.102.61.78".to_string(),
        ];
        let f = FilterBuilder::from_block_list(&ips, &[]).unwrap();
        assert!(f.contains("host 185.230.125.100"));
        assert!(f.contains("host 94.102.61.78"));
        assert!(f.contains("not"));
    }
}