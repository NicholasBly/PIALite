//! Talks to the PIA Lite guard service (DNS proxy / internet block / hotel
//! login) through the shared, authenticated control channel.

pub use pialite_common::status::{BlockMode, DnsHealth, GuardStatus as Status};

pub fn request(cmd: &str) -> Result<String, String> {
    pialite_common::ipc::request(cmd)
}

/// Status with a short time limit, so a stuck service can't stall the tray.
pub fn status() -> Option<Status> {
    pialite_common::ipc::request_within("status", std::time::Duration::from_secs(8)).ok().and_then(|j| serde_json::from_str(&j).ok())
}

/// The guard program: next to this one (every installer puts them
/// together), else where older installers put it.
pub fn guard_exe() -> std::path::PathBuf {
    let name = if cfg!(windows) { "pialite-guard.exe" } else { "pialite-guard" };
    if let Some(p) = std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.join(name))).filter(|p| p.is_file()) {
        return p;
    }
    if cfg!(windows) {
        std::env::var_os("ProgramFiles")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Program Files"))
            .join("PiaLite")
            .join(name)
    } else {
        std::path::PathBuf::from("/usr/bin").join(name)
    }
}

/// Words that may go on an elevated command line: letters, digits and
/// - , _ only (mode names, feature lists, a NextDNS profile ID, an account ID).
pub fn safe_arg(a: &str) -> bool {
    !a.is_empty() && a.len() <= 200 && a.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | ',' | '_'))
}

/// What this installation is (written by setup; readable by everyone).
#[derive(Default, Clone, Debug, PartialEq)]
pub struct Install {
    pub kind: String,
    pub features: Vec<String>,
    pub product_code: String,
}

pub fn install_record() -> Option<Install> {
    // the portable version says so next to the program (and installs nothing)
    let kind_file = std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.join("install-kind")));
    if kind_file.and_then(|f| std::fs::read_to_string(f).ok()).is_some_and(|k| k.trim() == "portable") {
        return Some(Install { kind: "portable".into(), ..Default::default() });
    }
    let path = if cfg!(windows) {
        std::path::PathBuf::from(std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into()))
            .join("PiaLite")
            .join("install.json")
    } else {
        std::path::PathBuf::from("/var/lib/pialite/install.json")
    };
    parse_install(&std::fs::read_to_string(path).ok()?)
}

pub fn parse_install(text: &str) -> Option<Install> {
    let v: serde_json::Value = serde_json::from_str(text).ok()?;
    Some(Install {
        kind: v["kind"].as_str().unwrap_or("").to_string(),
        features: v["features"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
        product_code: v["product_code"].as_str().unwrap_or("").to_string(),
    })
}

/// A newer release, as `pialite-guard check-update --json` reports it.
#[derive(Clone, Debug, PartialEq)]
pub struct Update {
    pub latest: String,
    pub one_click: bool,
    pub page: String,
}

pub fn parse_update(json: &str) -> Option<Update> {
    let v: serde_json::Value = serde_json::from_str(json.trim()).ok()?;
    if v["newer"].as_bool() != Some(true) {
        return None;
    }
    Some(Update {
        latest: v["latest"].as_str()?.to_string(),
        one_click: v["one_click"].as_bool().unwrap_or(false),
        page: v["page"]
            .as_str()
            .filter(|p| p.starts_with("https://github.com/"))
            .unwrap_or("https://github.com/NicholasBly/PIALite/releases")
            .to_string(),
    })
}

/// Ask the guard program (as this user - it only reads GitHub) whether a
/// newer release exists. None = up to date, or the check failed.
pub fn check_update() -> Option<Update> {
    let mut c = std::process::Command::new(guard_exe());
    c.args(["check-update", "--json"]).stdin(std::process::Stdio::null()).stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000);
    }
    let mut child = c.stdout(std::process::Stdio::piped()).spawn().ok()?;
    let until = std::time::Instant::now() + std::time::Duration::from_secs(90);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < until => std::thread::sleep(std::time::Duration::from_millis(200)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let out = child.wait_with_output().ok()?;
    parse_update(&String::from_utf8_lossy(&out.stdout))
}

pub fn provider_name(id: &str) -> &str {
    match id {
        "nextdns" | "" => "NextDNS",
        "cloudflare" => "Cloudflare",
        "quad9" => "Quad9",
        "adguard" => "AdGuard",
        "google" => "Google",
        "custom" => "your DNS server",
        other => other,
    }
}

/// The guard runs this optional feature (older guards: everything).
pub fn has_feature(g: &Status, name: &str) -> bool {
    g.features.as_ref().is_none_or(|f| f.iter().any(|x| x == name))
}

pub fn mmss(secs: u64) -> String {
    format!("{}:{:02}", secs / 60, secs % 60)
}

pub fn mode_label(m: BlockMode) -> &'static str {
    match m {
        BlockMode::Off => "Off",
        BlockMode::Startup => "At startup until VPN connects (then PIA's kill switch)",
        BlockMode::Always => "Always when VPN is not connected (includes startup)",
    }
}

/// One-line summary for the menu / panel, and whether it's a warning.
pub fn summary(g: Option<&Status>, conn: Option<&str>) -> (String, bool) {
    let Some(g) = g else { return ("Guard service not running - DNS may not work".into(), true) };
    if g.hotel {
        return (format!("Hotel login: VPN off - NOT protected for {} more", mmss(g.hotel_left)), true);
    }
    if !g.notice.is_empty() {
        // something the user should act on (e.g. no reconnect after a hotel login)
        return (g.notice.clone(), true);
    }
    if g.restore_pending {
        return ("PIA's kill switch not back after hotel login (retrying) - blocking when VPN is off".into(), true);
    }
    if !g.config_error.is_empty() {
        return ("Guard settings missing or damaged - re-run the installer (see guard.log)".into(), true);
    }
    if g.mode != BlockMode::Off && !g.armed {
        return ("Internet block could NOT be set (see guard.log)".into(), true);
    }
    if !g.fw_error.is_empty() {
        // e.g. the rules couldn't be refreshed and the previous ones stay in use
        return ("Firewall problem - see guard.log (Unlock Internet if stuck offline)".into(), true);
    }
    let dns_on = has_feature(g, "dns");
    let name = provider_name(&g.dns_provider);
    if dns_on && !g.dns.listening {
        let why = if g.dns.bind_error.is_empty() { "starting".to_string() } else { g.dns.bind_error.clone() };
        return (format!("DNS proxy not running ({why})"), true);
    }
    if dns_on && !g.profile_set {
        return ("NextDNS profile not set - re-run the installer".into(), true);
    }
    if g.blocking && conn == Some("Connected") {
        // PIA says Connected, but the guard's own check of its adapter disagrees (F51-07)
        match g.tunnel_watch.as_str() {
            "down" => return ("Blocked: PIA says connected, but its network adapter is down".into(), true),
            "not-found" => return ("Blocked: PIA says connected, but PIA Lite can't find PIA's network adapter".into(), true),
            "checking" => return ("Checking PIA's network adapter...".into(), false),
            _ => {}
        }
    }
    if g.blocking {
        return ("Internet blocked until the VPN connects".into(), false);
    }
    if g.mode == BlockMode::Startup && g.pia_killswitch != "on" {
        return ("PIA kill switch isn't 'Always' - a VPN drop won't block traffic".into(), true);
    }
    if dns_on && conn == Some("Connected") && g.dns.health == DnsHealth::Down {
        return (format!("{name} not answering right now"), true);
    }
    let dns = match (dns_on, g.dns.health) {
        (false, _) => "Guard on".to_string(),
        (true, DnsHealth::Ok) => format!("{name} encrypted: OK"),
        (true, DnsHealth::Degraded) => format!("{name} encrypted: some lookups failed"),
        _ => format!("{name} encrypted DNS"),
    };
    let block = match g.mode {
        BlockMode::Off => "off",
        BlockMode::Startup => "at startup",
        BlockMode::Always => "always",
    };
    (format!("{dns}  |  Block: {block}"), false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pialite_common::status::DnsStatus;

    fn ok() -> Status {
        Status {
            mode: BlockMode::Startup,
            armed: true,
            profile_set: true,
            pia_killswitch: "on".into(),
            dns: DnsStatus { listening: true, health: DnsHealth::Ok, ..Default::default() },
            ..Default::default()
        }
    }

    #[test]
    fn records_and_updates() {
        let r = parse_install(
            r#"{"kind":"deb","version":"0.9.0","features":["guard","dns"],"dir":"/usr/bin","product_code":"","pia_task_disabled":false}"#,
        )
        .unwrap();
        assert_eq!(r.kind, "deb");
        assert_eq!(r.features, vec!["guard", "dns"]);
        assert!(parse_install("nope").is_none());
        let u = parse_update(r#"{"current":"0.9.0","latest":"0.9.1","newer":true,"signed":true,"one_click":true,"kind":"msi","page":"https://github.com/NicholasBly/PIALite/releases/tag/v0.9.1"}"#).unwrap();
        assert_eq!((u.latest.as_str(), u.one_click), ("0.9.1", true));
        assert!(parse_update(r#"{"latest":"0.9.0","newer":false}"#).is_none(), "up to date");
        let odd = parse_update(r#"{"latest":"9.9.9","newer":true,"page":"https://evil.example/"}"#).unwrap();
        assert!(odd.page.starts_with("https://github.com/"), "only GitHub pages are opened");
        assert!(safe_arg("guard,dns,hotel") && safe_arg("S-1-5-21-1-2-3") && safe_arg("abc123"));
        assert!(!safe_arg("a b") && !safe_arg("x;y") && !safe_arg("") && !safe_arg("http://x"));
    }

    #[test]
    fn optional_features_in_the_summary() {
        let no_dns = Status { features: Some(vec!["hotel".into()]), dns: Default::default(), ..ok() };
        assert_eq!(
            summary(Some(&no_dns), Some("Connected")).0,
            "Guard on  |  Block: at startup",
            "no DNS warning when DNS isn't installed"
        );
        let quad9 = Status { features: Some(vec!["dns".into()]), dns_provider: "quad9".into(), ..ok() };
        assert_eq!(summary(Some(&quad9), Some("Connected")).0, "Quad9 encrypted: OK  |  Block: at startup");
    }

    #[test]
    fn summaries() {
        assert_eq!(summary(Some(&ok()), Some("Connected")).0, "NextDNS encrypted: OK  |  Block: at startup");
        let blocked = Status { blocking: true, ..ok() };
        assert_eq!(summary(Some(&blocked), Some("Disconnected")), ("Internet blocked until the VPN connects".into(), false));
        let hotel = Status { hotel: true, hotel_left: 161, ..ok() };
        assert!(summary(Some(&hotel), None).0.contains("2:41"));
        let weak = Status { pia_killswitch: "auto".into(), ..ok() };
        assert!(summary(Some(&weak), Some("Connected")).1, "warns: startup mode relies on PIA's kill switch");
        let always = Status { mode: BlockMode::Always, pia_killswitch: "auto".into(), ..ok() };
        assert!(!summary(Some(&always), Some("Connected")).1, "always mode doesn't need PIA's kill switch");
        let nf = Status { mode: BlockMode::Always, blocking: true, tunnel_watch: "not-found".into(), ..ok() };
        assert!(summary(Some(&nf), Some("Connected")).1, "warns: can't confirm the tunnel");
        assert_eq!(summary(Some(&nf), Some("Disconnected")).0, "Internet blocked until the VPN connects");
        let fwe = Status { fw_error: "block rules could not be refreshed".into(), ..ok() };
        assert!(summary(Some(&fwe), Some("Connected")).1, "a firewall problem is shown, not hidden");
        let told = Status { notice: "The VPN didn't reconnect after the hotel login - press Connect".into(), ..ok() };
        assert_eq!(summary(Some(&told), Some("Disconnected")), (told.notice.clone(), true), "the guard's notice is shown");
        let unarmed = Status { armed: false, ..ok() };
        assert!(summary(Some(&unarmed), None).0.contains("could NOT"));
        assert!(summary(None, None).1);
    }
}
