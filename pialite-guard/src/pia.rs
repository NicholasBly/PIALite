//! PIA: its settings file (read only), and changes through piactl that are
//! read back to make sure they really took effect (audit P1-05, P2-18).

use pialite_common::piactl;
#[cfg(windows)]
use std::path::PathBuf;
use std::time::{Duration, Instant};

/// PIA's own programs - the same list PIA's kill switch always lets through
/// (PIA source, win_daemon.cpp productExecutables). Only existing files.
/// What PIA needs let through while everything else is blocked.
/// Windows: PIA's programs (by path). Linux (from PIA's own kill switch):
/// its daemon's group "piavpn" ("gid:N") and the mark on its kernel
/// WireGuard packets ("mark:N", 12817 + 2).
#[cfg(not(windows))]
pub fn engine_exes() -> Vec<String> {
    let mut v = vec![];
    if let Some(gid) = group_id("piavpn") {
        v.push(format!("gid:{gid}"));
    }
    v.push(format!("mark:{}", PIA_WG_MARK));
    v
}

/// Linux: the group PIA's daemon runs as (left out of the DNS redirect).
#[cfg(not(windows))]
pub fn engine_gid() -> Option<u32> {
    group_id("piavpn")
}

/// PIA's Linux WireGuard firewall mark (brandinfo linuxFwmarkBase 12817 + 2).
#[cfg(not(windows))]
pub const PIA_WG_MARK: u32 = 12819;

/// A group's id from /etc/group.
#[cfg(not(windows))]
pub fn group_id(name: &str) -> Option<u32> {
    let text = std::fs::read_to_string(std::env::var("PIALITE_GROUP_FILE").unwrap_or_else(|_| "/etc/group".into())).ok()?;
    parse_group(&text, name)
}

#[cfg(not(windows))]
pub fn parse_group(text: &str, name: &str) -> Option<u32> {
    text.lines().find_map(|l| {
        let mut f = l.split(':');
        (f.next()? == name).then(|| f.nth(1)?.parse().ok()).flatten()
    })
}

#[cfg(windows)]
pub fn engine_exes() -> Vec<String> {
    let d = piactl::pia_dir();
    ["pia-client.exe", "pia-service.exe", "pia-openvpn.exe", "pia-support-tool.exe", "pia-ss-local.exe", "pia-wgservice.exe"]
        .iter()
        .map(|f| d.join(f))
        .filter(|p| p.is_file())
        .map(|p: PathBuf| p.to_string_lossy().into_owned())
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub allow_lan: bool,
    pub killswitch: String,
}

/// Missing or unexpected values are an error, never a guess in the
/// permissive direction (audit P1-08).
pub fn parse_settings(text: &str) -> Result<Settings, String> {
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("PIA settings unreadable: {e}"))?;
    let allow_lan = v.get("allowLAN").and_then(|x| x.as_bool()).ok_or("PIA settings: allowLAN missing")?;
    let killswitch = v.get("killswitch").and_then(|x| x.as_str()).ok_or("PIA settings: killswitch missing")?.to_string();
    if !matches!(killswitch.as_str(), "on" | "auto" | "off") {
        return Err(format!("PIA settings: unknown killswitch value '{killswitch}'"));
    }
    Ok(Settings { allow_lan, killswitch })
}

pub fn read_settings() -> Result<Settings, String> {
    let text = std::fs::read_to_string(piactl::settings_path()).map_err(|e| format!("PIA settings file: {e}"))?;
    parse_settings(&text)
}

/// Allow LAN for the block rules: false unless PIA's settings positively say true.
pub fn allow_lan_or_safe() -> bool {
    #[cfg(test)]
    if let Some(v) = *TEST_LAN.lock().unwrap() {
        return v;
    }
    read_settings().map(|s| s.allow_lan).unwrap_or(false)
}

#[cfg(test)]
static TEST_LAN: std::sync::Mutex<Option<bool>> = std::sync::Mutex::new(None);

/// Tests: pretend PIA's Allow LAN is this (None = read the settings file).
#[cfg(test)]
pub fn set_test_allow_lan(v: Option<bool>) {
    *TEST_LAN.lock().unwrap() = v;
}

/// Set PIA's kill switch ("on" | "auto" | "off") and confirm it changed.
pub fn set_killswitch(value: &str) -> Result<(), String> {
    if !matches!(value, "on" | "auto" | "off") {
        return Err("bad kill switch value".into());
    }
    piactl::run(&["-u", "applysettings", &format!(r#"{{"killswitch":"{value}"}}"#)], piactl::T_SET)?;
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        match read_settings() {
            Ok(s) if s.killswitch == value => return Ok(()),
            Ok(s) if Instant::now() >= deadline => {
                return Err(format!("PIA kept its kill switch at '{}' (wanted '{value}')", s.killswitch));
            }
            Err(e) if Instant::now() >= deadline => return Err(e),
            _ => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

/// The DNS address PIA is pointed at so lookups reach the guard (Windows).
pub const PROXY_DNS: &str = "127.0.0.1";

/// PIA's DNS setting exactly as stored: "pia" (PIA's default, also when the
/// file doesn't name one), "hdns", "local", "" or a list of addresses.
pub fn read_override_dns() -> Result<serde_json::Value, String> {
    let text = std::fs::read_to_string(piactl::settings_path()).map_err(|e| format!("PIA settings file: {e}"))?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("PIA settings unreadable: {e}"))?;
    Ok(v.get("overrideDNS").cloned().unwrap_or_else(|| "pia".into()))
}

pub fn dns_is_proxy(v: &serde_json::Value) -> bool {
    v.as_array().is_some_and(|a| a.len() == 1 && a[0] == PROXY_DNS)
}

/// Set PIA's DNS setting and read it back from PIA's own settings file.
pub fn set_override_dns(value: &serde_json::Value) -> Result<(), String> {
    let ok = match value {
        serde_json::Value::String(_) => true,
        serde_json::Value::Array(a) => a.iter().all(|x| x.as_str().is_some_and(|s| s.parse::<std::net::IpAddr>().is_ok())),
        _ => false,
    };
    if !ok {
        return Err(format!("not a DNS setting PIA understands: {value}"));
    }
    let json = serde_json::json!({ "overrideDNS": value }).to_string();
    piactl::run(&["-u", "applysettings", &json], piactl::T_SET)?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match read_override_dns() {
            Ok(v) if &v == value => return Ok(()),
            Ok(v) if Instant::now() >= deadline => return Err(format!("PIA kept its DNS setting at {v} (wanted {value})")),
            Err(e) if Instant::now() >= deadline => return Err(e),
            _ => std::thread::sleep(Duration::from_millis(200)),
        }
    }
}

pub fn state() -> Result<String, String> {
    piactl::run(&["get", "connectionstate"], piactl::T_GET)
}

pub fn connect() -> Result<String, String> {
    piactl::run(&["connect"], piactl::T_CONNECT)
}

pub fn disconnect() -> Result<String, String> {
    piactl::run(&["disconnect"], piactl::T_CONNECT)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn settings() {
        let s = parse_settings(r#"{"allowLAN":false,"killswitch":"on","overrideDNS":["127.0.0.1"]}"#).unwrap();
        assert_eq!(s, Settings { allow_lan: false, killswitch: "on".into() });
        assert!(parse_settings("garbage").is_err());
        assert!(parse_settings(r#"{"killswitch":"on"}"#).is_err(), "missing allowLAN is an error, not 'true'");
        assert!(parse_settings(r#"{"allowLAN":true,"killswitch":"maybe"}"#).is_err());
    }
}
