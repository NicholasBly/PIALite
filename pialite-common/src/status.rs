//! The guard's status report, shared by the service (writer) and the tray /
//! command line (readers). Unknown fields are ignored and missing ones get
//! defaults, so a newer tray can still read an older guard and vice versa.

use serde::{Deserialize, Serialize};

/// What the internet block does.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum BlockMode {
    /// No block.
    #[default]
    Off,
    /// Blocked from boot (and after sleep/wake, or if PIA's service stops)
    /// until PIA first reports Connected; then PIA's own kill switch is in charge.
    Startup,
    /// Blocked whenever PIA is not freshly reported Connected with its
    /// network adapter observed up.
    Always,
}

impl BlockMode {
    pub fn parse(s: &str) -> Option<BlockMode> {
        match s {
            "off" => Some(BlockMode::Off),
            "startup" => Some(BlockMode::Startup),
            "always" => Some(BlockMode::Always),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            BlockMode::Off => "off",
            BlockMode::Startup => "startup",
            BlockMode::Always => "always",
        }
    }
    /// Off < Startup < Always. Moving down needs an administrator.
    pub fn strength(self) -> u8 {
        match self {
            BlockMode::Off => 0,
            BlockMode::Startup => 1,
            BlockMode::Always => 2,
        }
    }
    pub fn weaker_than(self, other: BlockMode) -> bool {
        self.strength() < other.strength()
    }
}

/// How the encrypted DNS proxy is doing, judged over recent lookups rather
/// than just the last one (audit P2-21).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum DnsHealth {
    /// No lookups answered or failed yet.
    #[default]
    Untested,
    /// Recent lookups answered.
    Ok,
    /// Some recent lookups failed, the latest worked.
    Degraded,
    /// Lookups are failing (NextDNS unreachable).
    Down,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct DnsStatus {
    pub listening: bool,
    pub bind_error: String,
    pub health: DnsHealth,
    pub last_error: String,
    pub last_ms: u64,
    /// Seconds since the last successful lookup.
    pub last_ok_age: Option<u64>,
    pub answered: u64,
    pub failed: u64,
    /// Refused because the queue was full.
    pub overloaded: u64,
    /// Not a valid DNS query, ignored.
    pub malformed: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct GuardStatus {
    pub proto: u32,
    pub version: String,
    pub mode: BlockMode,
    /// Persistent block rules are in place (checked against Windows, not just remembered).
    pub armed: bool,
    /// Boot-time rules (active before Windows' filtering engine starts) are in place.
    pub boot_rules: bool,
    pub boot_rules_error: String,
    /// The block is currently stopping traffic.
    pub blocking: bool,
    /// Plain-words reason for the current state.
    pub reason: String,
    pub hotel: bool,
    pub hotel_left: u64,
    pub hotel_minutes: u32,
    /// Hotel login ended but PIA's kill switch setting could not be put back yet.
    pub restore_pending: bool,
    pub pia_state: Option<String>,
    pub pia_killswitch: String,
    pub pia_allow_lan: bool,
    pub profile_set: bool,
    pub dns: DnsStatus,
    pub config_error: String,
    pub fw_error: String,
    /// Windows accounts (besides admins) allowed to use the control pipe.
    pub approved_accounts: u32,
    /// PIA's adapter carrying the current VPN connection and whether it is up
    /// ("" = none seen for this connection).
    pub vpn_adapter: String,
    /// The second, independent check of the VPN (review F51-07), as one of the
    /// TunnelWatch words: "" = VPN not connected, "checking", "up", "down",
    /// "not-found", "query-failed".
    pub tunnel_watch: String,
    /// What the guard WANTS in Windows right now, separate from what it sees
    /// (review F51-03): block rules (effective mode not off) and boot-time
    /// rules (also the boot-time setting). None = an older guard.
    pub rules_wanted: Option<bool>,
    pub boot_rules_wanted: Option<bool>,
    /// The mode deciding the rules right now: stricter than `mode` while PIA's
    /// kill switch isn't back after a hotel login. None = an older guard.
    pub effective_mode: Option<BlockMode>,
    /// A usable network (an adapter other than PIA's with an address and a
    /// gateway) - PIA is only asked to connect once there is one.
    pub network_ready: Option<bool>,
    /// Information only (review V60-08): does Windows' route to NextDNS go
    /// through the PIA adapter that was observed up? None = not known / no
    /// VPN. "Observed up" is what Windows reports about the adapter - not a
    /// proof that the encrypted tunnel works.
    pub route_via_vpn: Option<bool>,
    /// Something the user should do, in plain words ("" = nothing), e.g. the
    /// reconnect after a hotel login failed (review V65-02).
    pub notice: String,
    /// Optional features this guard runs (0.9): "dns", "hotel". None = an
    /// older guard (everything on).
    pub features: Option<Vec<String>>,
    /// The encrypted DNS provider in use ("" = encrypted DNS off).
    pub dns_provider: String,
    /// It is reached over DNS over TLS (port 853), not HTTPS.
    pub dns_tls: bool,
    /// Plain DNS can only go through the guard right now: Windows - DNS to
    /// other servers is blocked; Linux - it is redirected to the proxy.
    /// None = an older guard / encrypted DNS off.
    pub dns_only_guard: Option<bool>,
    /// Why it isn't on right now (or why it couldn't be changed/checked),
    /// in plain words; "" = on, or encrypted DNS off.
    pub dns_only_guard_note: String,
}

/// The guard's tunnel check, in words (GuardStatus::tunnel_watch).
pub mod tunnel_watch {
    pub const OFF: &str = "";
    pub const CHECKING: &str = "checking";
    pub const UP: &str = "up";
    pub const DOWN: &str = "down";
    pub const NOT_FOUND: &str = "not-found";
    pub const QUERY_FAILED: &str = "query-failed";
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn roundtrip_and_tolerance() {
        let s = GuardStatus { proto: 2, mode: BlockMode::Always, blocking: true, ..Default::default() };
        let j = serde_json::to_string(&s).unwrap();
        assert!(j.contains("\"mode\":\"always\""));
        assert_eq!(serde_json::from_str::<GuardStatus>(&j).unwrap(), s);
        // older/newer peers: unknown fields ignored, missing ones defaulted
        let s: GuardStatus = serde_json::from_str(r#"{"mode":"startup","future_field":1}"#).unwrap();
        assert_eq!(s.mode, BlockMode::Startup);
        assert_eq!(s.dns.health, DnsHealth::Untested);
        assert_eq!(BlockMode::parse("always"), Some(BlockMode::Always));
        assert_eq!(BlockMode::parse("ALWAYS"), None);
        assert!(BlockMode::Off.weaker_than(BlockMode::Startup) && BlockMode::Startup.weaker_than(BlockMode::Always));
        assert!(!BlockMode::Always.weaker_than(BlockMode::Always) && !BlockMode::Always.weaker_than(BlockMode::Off));
    }
}
