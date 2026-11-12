//! Settings file (%ProgramData%\PiaLite\guard.json), its last-known-good copy
//! (guard.json.bak) and the log file.
//!
//! Loading never silently weakens protection (audit P1-04, review N-03): a
//! missing, damaged or unreadable file falls back to the last good copy, and
//! failing that - if our block rules are in Windows - to a protective setting,
//! and the problem is reported in the status. Only "no file, no backup, no
//! rules" counts as a fresh install (defaults, block off).

use pialite_common::status::BlockMode;
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(default)]
pub struct Config {
    pub mode: BlockMode,
    /// Old (v0.1) setting, read once and turned into `mode`.
    #[serde(skip_serializing)]
    pub boot_block: Option<bool>,
    /// Also add boot-time rules, active before Windows' filtering engine starts.
    pub boot_time_rules: bool,
    /// NextDNS profile ID (from my.nextdns.io).
    pub profile_id: String,
    /// Name this PC shows up as in NextDNS logs.
    pub device_name: String,
    pub doh_host: String,
    /// NextDNS anycast IPs, so the proxy never needs DNS to find NextDNS.
    pub doh_bootstrap: Vec<String>,
    /// While blocked after boot/wake, ask PIA to connect right away.
    pub connect_at_boot: bool,
    pub hotel_minutes: u32,
    /// Windows accounts (SIDs) allowed to control the guard, besides SYSTEM and Administrators.
    pub allowed_sids: Vec<String>,
    /// Linux: user ids allowed to control the guard, besides root.
    pub allowed_uids: Vec<u32>,
    /// Hotel-mode recovery marker: set before PIA's kill switch is touched,
    /// cleared only once the original setting is verified back in place.
    pub hotel_active: bool,
    pub hotel_saved_killswitch: String,
    /// Optional features (0.9). Missing in files from older versions - then
    /// everything they had is on (see `features()`).
    #[serde(default)]
    pub features: Option<Features>,
    /// Encrypted DNS provider: one of `DNS_PRESETS` ids, or "custom".
    /// "" in files from older versions = NextDNS.
    pub dns_provider: String,
    /// URL path for the "custom" provider (e.g. /dns-query).
    pub doh_custom_path: String,
    /// custom server: DNS over TLS (tls://host) instead of HTTPS
    pub doh_custom_dot: bool,
    /// custom server: its port (0 = 443 for HTTPS, 853 for TLS)
    pub doh_custom_port: u16,
    /// custom server: trust only the certificate authority in
    /// <data folder>/custom-ca.pem (a home server such as Pi-hole with its own CA)
    pub doh_custom_ca: bool,
}

/// What this installation uses, chosen in the installer (0.9).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Default)]
#[serde(default)]
pub struct Features {
    /// Encrypted DNS through the guard's local DNS proxy.
    pub dns: bool,
    /// Hotel / captive-portal login helper.
    pub hotel: bool,
}

/// A ready-made encrypted DNS (DoH) provider. Addresses are used so the
/// proxy never needs DNS to find its DNS server.
pub struct DnsPreset {
    pub id: &'static str,
    pub name: &'static str,
    pub host: &'static str,
    pub path: &'static str,
    pub bootstrap: &'static [&'static str],
    /// DNS over TLS (port 853) instead of DNS over HTTPS: Quad9 ended DoH
    /// over HTTP/1.1 in Dec 2025 (it answers "HTTP 505"), DoT still works.
    pub dot: bool,
}

/// Checked against the providers' own pages, 2026-11 (Mullvad's public DNS
/// ended 2026-11-02, so it isn't offered).
pub const DNS_PRESETS: &[DnsPreset] = &[
    DnsPreset {
        id: "nextdns",
        name: "NextDNS (your profile)",
        host: "dns.nextdns.io",
        path: "",
        bootstrap: &["45.90.28.0", "45.90.30.0", "2a07:a8c0::", "2a07:a8c1::"],
        dot: false,
    },
    DnsPreset {
        id: "cloudflare",
        name: "Cloudflare",
        host: "cloudflare-dns.com",
        path: "/dns-query",
        bootstrap: &["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
        dot: false,
    },
    DnsPreset {
        id: "quad9",
        name: "Quad9 (blocks malware)",
        host: "dns.quad9.net",
        path: "/dns-query",
        bootstrap: &["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
        dot: true,
    },
    DnsPreset {
        id: "adguard",
        name: "AdGuard (blocks ads and trackers)",
        host: "dns.adguard-dns.com",
        path: "/dns-query",
        bootstrap: &["94.140.14.14", "94.140.15.15", "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff"],
        dot: false,
    },
    DnsPreset {
        id: "google",
        name: "Google Public DNS",
        host: "dns.google",
        path: "/dns-query",
        bootstrap: &["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
        dot: false,
    },
];

pub fn preset(id: &str) -> Option<&'static DnsPreset> {
    DNS_PRESETS.iter().find(|p| p.id == id)
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: BlockMode::Off,
            boot_block: None,
            boot_time_rules: true,
            profile_id: String::new(),
            device_name: std::env::var("COMPUTERNAME").unwrap_or_default(),
            doh_host: "dns.nextdns.io".into(),
            doh_bootstrap: vec!["45.90.28.0".into(), "45.90.30.0".into()],
            connect_at_boot: true,
            hotel_minutes: 3,
            allowed_sids: Vec::new(),
            allowed_uids: Vec::new(),
            hotel_active: false,
            hotel_saved_killswitch: String::new(),
            // no choice recorded = everything on, as before 0.9; the
            // installers' `setup` always records the user's choice
            features: None,
            dns_provider: "nextdns".into(),
            doh_custom_path: String::new(),
            doh_custom_dot: false,
            doh_custom_port: 0,
            doh_custom_ca: false,
        }
    }
}

impl Config {
    /// The features in effect: older files (no `features`) had DNS and hotel
    /// login always on.
    pub fn features(&self) -> Features {
        self.features.unwrap_or(Features { dns: true, hotel: true })
    }

    /// The DNS provider id in effect ("" in older files = NextDNS).
    pub fn provider(&self) -> &str {
        if self.dns_provider.is_empty() {
            "nextdns"
        } else {
            &self.dns_provider
        }
    }

    /// Switch to a provider: host, path and addresses from the preset, or -
    /// for "custom" - from `custom` (https URL + at least one IP address).
    pub fn set_provider(&mut self, id: &str, custom: Option<(&str, &[String])>) -> Result<(), String> {
        if id == "custom" {
            let (url, ips) = custom.ok_or("custom DNS needs a URL and its IP addresses")?;
            let u = parse_server_url(url)?;
            if ips.is_empty() || ips.iter().any(|ip| ip.parse::<std::net::IpAddr>().is_err()) {
                return Err("custom DNS needs at least one valid IP address for the server (it is never looked up by name)".into());
            }
            self.doh_host = u.host;
            self.doh_custom_path = u.path;
            self.doh_custom_dot = u.dot;
            self.doh_custom_port = u.port;
            self.doh_custom_ca = false; // the caller turns it on with the file in place
            self.doh_bootstrap = ips.to_vec();
        } else {
            let p = preset(id).ok_or_else(|| format!("unknown DNS provider '{id}' (use: {}, custom)", preset_ids()))?;
            self.doh_host = p.host.into();
            self.doh_bootstrap = p.bootstrap.iter().map(|s| s.to_string()).collect();
            self.doh_custom_path.clear();
            self.doh_custom_dot = false;
            self.doh_custom_port = 0;
            self.doh_custom_ca = false;
        }
        self.dns_provider = id.into();
        Ok(())
    }

    /// URL path for DoH. NextDNS: /<profile>/<device>, only letters, digits
    /// and dashes; other presets: their path; custom: the path given.
    /// DNS over TLS for this provider (see DnsPreset::dot)?
    pub fn dot(&self) -> bool {
        if self.provider() == "custom" {
            return self.doh_custom_dot;
        }
        preset(self.provider()).is_some_and(|p| p.dot)
    }

    /// The server's port: a custom one if given, else 853 (TLS) / 443 (HTTPS).
    pub fn port(&self) -> u16 {
        match (self.provider() == "custom" && self.doh_custom_port != 0, self.dot()) {
            (true, _) => self.doh_custom_port,
            (false, true) => 853,
            (false, false) => 443,
        }
    }

    /// The custom server as typed (tls://host[:port] or https://host[:port]/path).
    pub fn custom_url(&self) -> String {
        let port = if self.doh_custom_port != 0 { format!(":{}", self.doh_custom_port) } else { String::new() };
        if self.doh_custom_dot {
            format!("tls://{}{port}", self.doh_host)
        } else {
            format!("https://{}{port}{}", self.doh_host, self.doh_custom_path)
        }
    }

    /// Every server address is on the local network (a home DNS server).
    pub fn server_is_local(&self) -> bool {
        !self.doh_bootstrap.is_empty() && self.doh_bootstrap.iter().all(|ip| ip.parse::<std::net::IpAddr>().is_ok_and(is_local_ip))
    }

    pub fn doh_path(&self) -> String {
        match self.provider() {
            "nextdns" => {}
            "custom" => return self.doh_custom_path.clone(),
            other => return preset(other).map(|p| p.path.to_string()).unwrap_or_else(|| "/dns-query".into()),
        }
        let profile: String = self.profile_id.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
        let device: String = self
            .device_name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>()
            .trim_matches('-')
            .chars()
            .take(40)
            .collect();
        match (profile.is_empty(), device.is_empty()) {
            (true, _) => "/dns-query".into(),
            (false, true) => format!("/{profile}"),
            (false, false) => format!("/{profile}/{device}"),
        }
    }

    pub fn validate(mut self) -> Result<Config, String> {
        if let Some(true) = self.boot_block.take() {
            if self.mode == BlockMode::Off {
                self.mode = BlockMode::Startup; // migrate v0.1 setting
            }
        }
        if !self.profile_id.is_empty() && !valid_profile(&self.profile_id) {
            return Err("profile_id is not a valid NextDNS ID".into());
        }
        if !self.dns_provider.is_empty() && self.dns_provider != "custom" && preset(&self.dns_provider).is_none() {
            return Err(format!("dns_provider '{}' is not known", self.dns_provider));
        }
        if self.dns_provider == "custom" && (parse_server_url(&self.custom_url()).is_err() || self.doh_bootstrap.is_empty()) {
            return Err("custom DNS provider: invalid host/path or no IP address".into());
        }
        if self.doh_bootstrap.iter().any(|ip| ip.parse::<std::net::IpAddr>().is_err()) {
            return Err("doh_bootstrap has an invalid IP address".into());
        }
        if self.allowed_sids.iter().any(|s| !valid_sid(s)) {
            return Err("allowed_sids has an invalid entry".into());
        }
        self.hotel_minutes = self.hotel_minutes.clamp(1, 15);
        Ok(self)
    }
}

pub fn preset_ids() -> String {
    DNS_PRESETS.iter().map(|p| p.id).collect::<Vec<_>>().join(", ")
}

/// https://host[:443]/path -> (host, path). Only https, a plain host name
/// (letters, digits, dots, dashes) and a path without spaces or quotes.
/// A custom encrypted DNS server: `https://host[:port][/path]` (DNS over
/// HTTPS, path defaults to /dns-query) or `tls://host[:port]` (DNS over TLS).
#[derive(Debug, Clone, PartialEq)]
pub struct ServerUrl {
    pub host: String,
    pub path: String,
    /// 0 = the default (443 / 853)
    pub port: u16,
    pub dot: bool,
}

pub fn parse_server_url(url: &str) -> Result<ServerUrl, String> {
    let (dot, rest) = if let Some(r) = url.strip_prefix("https://") {
        (false, r)
    } else if let Some(r) = url.strip_prefix("tls://") {
        (true, r)
    } else {
        return Err("the server must start with https:// (DNS over HTTPS) or tls:// (DNS over TLS)".into());
    };
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/dns-query"),
    };
    if dot && path != "/dns-query" && path != "/" {
        return Err("a tls:// server has no path".into());
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h, p.parse::<u16>().ok().filter(|p| *p != 0).ok_or(format!("'{p}' is not a port number"))?),
        None => (hostport, 0),
    };
    let port = if (!dot && port == 443) || (dot && port == 853) { 0 } else { port };
    let ok_host = !host.is_empty()
        && host.len() <= 253
        && host.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
        && !host.starts_with(['.', '-'])
        && host.contains('.');
    if !ok_host {
        return Err(format!("'{host}' is not a valid server name"));
    }
    if path.len() > 200 || path.chars().any(|c| c.is_whitespace() || c.is_control() || c == '"' || c == '\\') {
        return Err("the DNS URL path has characters that aren't allowed".into());
    }
    Ok(ServerUrl { host: host.to_ascii_lowercase(), path: if dot { String::new() } else { path.to_string() }, port, dot })
}

/// Private / link-local / unique-local addresses (a server at home).
pub fn is_local_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(a) => a.is_private() || a.is_link_local() || a.is_loopback(),
        std::net::IpAddr::V6(a) => (a.segments()[0] & 0xfe00) == 0xfc00 || (a.segments()[0] & 0xffc0) == 0xfe80 || a.is_loopback(),
    }
}

/// The file with a custom server's certificate authority (PEM).
pub fn custom_ca_path() -> PathBuf {
    data_dir().join("custom-ca.pem")
}

/// Check a PEM file holds at least one certificate (and nothing huge).
pub fn check_ca_pem(pem: &[u8]) -> Result<usize, String> {
    use rustls::pki_types::{pem::PemObject, CertificateDer};
    if pem.len() > 64 * 1024 {
        return Err("the certificate file is too big (over 64 KB)".into());
    }
    let certs: Vec<_> =
        CertificateDer::pem_slice_iter(pem).collect::<Result<_, _>>().map_err(|e| format!("not a PEM certificate file: {e:?}"))?;
    let mut roots = rustls::RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err("no usable certificate in that file (it must be PEM: -----BEGIN CERTIFICATE-----)".into());
    }
    Ok(added)
}

pub fn valid_profile(id: &str) -> bool {
    (4..=12).contains(&id.len()) && id.chars().all(|c| c.is_ascii_alphanumeric())
}

/// A Windows SID string like S-1-5-21-1234-5678-9012-1001.
pub fn valid_sid(s: &str) -> bool {
    let mut parts = s.split('-');
    parts.next() == Some("S")
        && parts.next() == Some("1")
        && s.len() <= 184
        && s.split('-').skip(2).count() >= 2
        && s.split('-').skip(2).all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
}

pub fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("PIALITE_DATA") {
        return PathBuf::from(d);
    }
    #[cfg(all(windows, not(test)))]
    {
        let base = std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into());
        PathBuf::from(base).join("PiaLite")
    }
    #[cfg(all(target_os = "linux", not(test)))]
    {
        PathBuf::from("/var/lib/pialite")
    }
    #[cfg(any(test, not(any(windows, target_os = "linux"))))]
    {
        std::env::temp_dir().join("pialite")
    }
}

fn path() -> PathBuf {
    data_dir().join("guard.json")
}
fn backup_path() -> PathBuf {
    data_dir().join("guard.json.bak")
}

pub enum Loaded {
    /// Normal.
    Ok(Config),
    /// No settings file, no backup, no block rules: a fresh install.
    Fresh(Config),
    /// The file was missing or damaged; this is the best safe substitute and why.
    Recovered(Config, String),
}

impl Loaded {
    pub fn config(&self) -> &Config {
        match self {
            Loaded::Ok(c) | Loaded::Fresh(c) | Loaded::Recovered(c, _) => c,
        }
    }
}

fn read(p: &std::path::Path) -> Result<Option<Config>, String> {
    match std::fs::read_to_string(p) {
        Ok(text) => serde_json::from_str::<Config>(&text).map_err(|e| e.to_string()).and_then(Config::validate).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// `rules_present`: are our block rules currently installed in Windows? Used
/// to fail closed when the settings can't be read.
pub fn load(rules_present: impl FnOnce() -> bool) -> Loaded {
    let (why, damaged) = match read(&path()) {
        Ok(Some(c)) => return Loaded::Ok(c),
        Ok(None) => ("guard.json is missing".to_string(), false),
        Err(e) => (format!("guard.json is damaged ({e})"), true),
    };
    if damaged {
        let _ = std::fs::copy(path(), data_dir().join("guard.json.broken"));
    }
    if let Ok(Some(c)) = read(&backup_path()) {
        let why = format!("{why} - using the last good copy");
        log(&why);
        return Loaded::Recovered(c, why);
    }
    if rules_present() {
        // the block was on: keep it (Startup = blocked until the VPN connects)
        let c = Config { mode: BlockMode::Startup, ..Config::default() };
        let why = format!("{why} and there is no good backup, but block rules are installed - kept the block on; re-run the installer");
        log(&why);
        return Loaded::Recovered(c, why);
    }
    if !damaged {
        return Loaded::Fresh(Config::default());
    }
    let why = format!("{why} and there is no good backup (no block rules were installed) - re-run the installer");
    log(&why);
    Loaded::Recovered(Config::default(), why)
}

/// Write `text` to a temp file next to `target`, flush it to disk, then
/// rename it over `target` (all or nothing). `before_rename` runs just before.
fn write_durable(target: &std::path::Path, text: &str, before_rename: impl FnOnce()) -> Result<(), String> {
    let dir = data_dir();
    std::fs::create_dir_all(&dir).map_err(|e| format!("settings folder: {e}"))?;
    let name = target.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = dir.join(format!("{name}.{}.tmp", std::process::id()));
    let write = || -> std::io::Result<()> {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(text.as_bytes())?;
        f.sync_all()
    };
    if let Err(e) = write() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("could not save {name}: {e}"));
    }
    before_rename();
    std::fs::rename(&tmp, target).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("could not save {name}: {e}")
    })
}

/// Durable write: temp file, flush to disk, keep the previous good file as
/// .bak, then atomic rename over guard.json.
pub fn save(cfg: &Config) -> Result<(), String> {
    let text = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    write_durable(&path(), &text, || {
        if matches!(read(&path()), Ok(Some(_))) {
            let _ = std::fs::copy(path(), backup_path());
        }
    })
}

// ------------------------------------------------------- hotel recovery record

/// What a hotel login changed and must be put back. Kept in its OWN file
/// (hotel-recovery.json), written durably BEFORE PIA's kill switch is relaxed
/// and removed only after it is verified back. Normal settings saves never
/// rotate it, so a damaged guard.json falling back to an older .bak can't make
/// an unfinished restore look finished (review V4-03).
///
/// File format, version 1 (review F51-01; the uninstaller's PowerShell reader
/// applies exactly the same rules, checked against tests/windows/scripts/recovery-fixtures.json):
///   {"version": 1, "hotel": <whole number 1..2^53-1>, "saved_killswitch": "on"|"auto"|"off"}
/// No other fields; names are case-sensitive. "version" may be missing
/// (written by v0.5.x). Anything else is DAMAGED - never "nothing to do".
#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Recovery {
    pub version: u32,
    pub hotel: u64,
    pub saved_killswitch: String,
}

pub const RECOVERY_VERSION: u32 = 1;
/// Largest whole number JSON readers agree on (PowerShell and Rust alike).
const MAX_SAFE: u64 = (1 << 53) - 1;

impl Recovery {
    pub fn new(hotel: u64, saved_killswitch: &str) -> Recovery {
        Recovery { version: RECOVERY_VERSION, hotel, saved_killswitch: saved_killswitch.into() }
    }
}

fn valid_killswitch(v: &str) -> bool {
    matches!(v, "on" | "auto" | "off")
}

/// The largest hotel-recovery.json either reader accepts (a real one is ~60 bytes).
pub const RECOVERY_MAX_LEN: usize = 4096;

/// Every field name in a JSON text, as written (escapes not decoded): a name
/// is a string followed by ':'. The same simple scan the uninstaller's
/// PowerShell reader does (Test-JsonKeys), so both see the same names.
fn json_key_tokens(text: &str) -> Vec<&str> {
    let b = text.as_bytes();
    let mut keys = vec![];
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'"' {
            i += 1;
            continue;
        }
        let mut j = i + 1;
        let mut esc = false;
        while j < b.len() {
            if esc {
                esc = false;
            } else if b[j] == b'\\' {
                esc = true;
            } else if b[j] == b'"' {
                break;
            }
            j += 1;
        }
        let tok = &text[i + 1..j.min(b.len())];
        let mut k = j + 1;
        while k < b.len() && matches!(b[k], b' ' | b'\t' | b'\r' | b'\n') {
            k += 1;
        }
        if k < b.len() && b[k] == b':' {
            keys.push(tok);
        }
        i = j + 1;
    }
    keys
}

/// Field names must be unambiguous (review V60-11): no name twice - also not
/// in different capitals (PowerShell 5.1 merges those) - and no escape codes
/// in a name (they could spell a name twice in different ways).
pub fn json_keys_ok(text: &str) -> Result<(), String> {
    let keys = json_key_tokens(text);
    if let Some(k) = keys.iter().find(|k| k.contains('\\')) {
        return Err(format!("a field name uses escape codes ({k})"));
    }
    let mut seen = std::collections::HashSet::new();
    for k in keys {
        if !seen.insert(k.to_ascii_lowercase()) {
            return Err(format!("field '{k}' appears twice"));
        }
    }
    Ok(())
}

/// The strict reader for hotel-recovery.json.
pub fn parse_recovery(text: &str) -> Result<Recovery, String> {
    if text.len() > RECOVERY_MAX_LEN {
        return Err(format!("{} bytes - too big to be a recovery record", text.len()));
    }
    json_keys_ok(text)?;
    let v: serde_json::Value = serde_json::from_str(text).map_err(|e| format!("not valid JSON ({e})"))?;
    let o = v.as_object().ok_or("not a JSON object")?;
    if let Some(k) = o.keys().find(|k| !matches!(k.as_str(), "version" | "hotel" | "saved_killswitch")) {
        return Err(format!("unexpected field '{k}'"));
    }
    let version = match o.get("version") {
        None => RECOVERY_VERSION,
        Some(n) if n.is_u64() && n.as_u64() == Some(RECOVERY_VERSION as u64) => RECOVERY_VERSION,
        Some(n) => return Err(format!("unknown version {n}")),
    };
    let hotel = match o.get("hotel") {
        Some(n) if n.is_u64() => n.as_u64().unwrap_or(0),
        Some(n) => return Err(format!("'hotel' must be a whole number, not {n}")),
        None => return Err("'hotel' is missing".into()),
    };
    if !(1..=MAX_SAFE).contains(&hotel) {
        return Err(format!("'hotel' {hotel} is out of range"));
    }
    let saved = match o.get("saved_killswitch") {
        Some(serde_json::Value::String(s)) if valid_killswitch(s) => s.clone(),
        Some(x) => return Err(format!("unknown kill switch value {x}")),
        None => return Err("'saved_killswitch' is missing".into()),
    };
    Ok(Recovery { version, hotel, saved_killswitch: saved })
}

#[derive(Debug, PartialEq)]
pub enum RecoveryState {
    None,
    Pending(Recovery),
    /// The file is there but can't be read: a restore IS outstanding.
    Damaged(String),
}

/// guard.json's own hotel marker, as far as it can be read.
#[derive(Debug, PartialEq)]
pub enum Marker {
    /// guard.json missing or unreadable (the uninstaller's view - see marker_from_text).
    #[cfg_attr(not(test), allow(dead_code))]
    Unreadable(String),
    Read {
        active: bool,
        saved: String,
    },
}

/// What the records say about an unfinished hotel login.
#[derive(Debug, PartialEq)]
pub enum Verdict {
    /// Nothing outstanding.
    None,
    /// Put PIA's kill switch back to this (it was relaxed only if "on").
    Restore(String),
    /// The records are damaged or disagree: the guard assumes "on"; the
    /// uninstaller asks you to check PIA yourself.
    Unknown(String),
}

/// One rule for every reader (the guard, `show-rules`, and - in PowerShell -
/// the uninstaller): the recovery record decides; guard.json's marker only
/// counts when there is no record, and a disagreement between the two is
/// never resolved by guessing.
pub fn decide(record: &RecoveryState, marker: &Marker) -> Verdict {
    match (record, marker) {
        (RecoveryState::Damaged(e), _) => Verdict::Unknown(format!("the hotel recovery record is damaged: {e}")),
        (RecoveryState::Pending(r), Marker::Read { active: true, saved }) if *saved != r.saved_killswitch => {
            Verdict::Unknown(format!("the hotel recovery record ('{}') and guard.json ('{saved}') disagree", r.saved_killswitch))
        }
        (RecoveryState::Pending(r), _) => Verdict::Restore(r.saved_killswitch.clone()),
        (RecoveryState::None, Marker::Unreadable(e)) => Verdict::Unknown(e.clone()),
        (RecoveryState::None, Marker::Read { active: true, saved }) if valid_killswitch(saved) => Verdict::Restore(saved.clone()),
        (RecoveryState::None, Marker::Read { active: true, saved }) => {
            Verdict::Unknown(format!("guard.json records a hotel login with an unknown kill switch value '{saved}'"))
        }
        (RecoveryState::None, Marker::Read { active: false, .. }) => Verdict::None,
    }
}

/// The verdict for the loaded settings (what the guard and `show-rules` use).
pub fn verdict_for(cfg: &Config) -> Verdict {
    decide(&load_recovery(), &Marker::Read { active: cfg.hotel_active, saved: cfg.hotel_saved_killswitch.clone() })
}

/// Would the guard act as Always because of an unfinished hotel login?
/// (PIA's kill switch relaxed and not verified back, or the records can't tell.)
pub fn strict_for(cfg: &Config) -> bool {
    match verdict_for(cfg) {
        Verdict::None => false,
        Verdict::Restore(s) => s == "on",
        Verdict::Unknown(_) => true,
    }
}

/// guard.json's marker from the file's text, read the way the uninstaller
/// reads it (only the two hotel fields matter; they must have the right
/// types). The guard itself reads guard.json through `load`; this is the
/// uninstaller's view, kept here so both are tested on the same fixtures.
#[cfg(test)]
pub fn marker_from_text(text: Option<&str>) -> Marker {
    let Some(text) = text else { return Marker::Unreadable("guard.json is missing".into()) };
    if let Err(e) = json_keys_ok(text) {
        return Marker::Unreadable(format!("guard.json: {e}"));
    }
    let v: serde_json::Value = match serde_json::from_str(text) {
        Ok(v) => v,
        Err(e) => return Marker::Unreadable(format!("guard.json can't be read ({e})")),
    };
    let Some(o) = v.as_object() else { return Marker::Unreadable("guard.json is not a JSON object".into()) };
    let active = match o.get("hotel_active") {
        None => false,
        Some(serde_json::Value::Bool(b)) => *b,
        Some(x) => return Marker::Unreadable(format!("guard.json: hotel_active is {x}, not true/false")),
    };
    let saved = match o.get("hotel_saved_killswitch") {
        None => String::new(),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(x) => return Marker::Unreadable(format!("guard.json: hotel_saved_killswitch is {x}, not text")),
    };
    Marker::Read { active, saved }
}

/// The record's state from the file's text (None = no file).
pub fn record_from_text(text: Option<&str>) -> RecoveryState {
    match text {
        None => RecoveryState::None,
        Some(t) => match parse_recovery(t) {
            Ok(r) => RecoveryState::Pending(r),
            Err(e) => RecoveryState::Damaged(e),
        },
    }
}

fn recovery_path() -> PathBuf {
    data_dir().join("hotel-recovery.json")
}

pub fn load_recovery() -> RecoveryState {
    match std::fs::read_to_string(recovery_path()) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => RecoveryState::None,
        Err(e) => RecoveryState::Damaged(e.to_string()),
        Ok(text) => record_from_text(Some(&text)),
    }
}

pub fn save_recovery(r: &Recovery) -> Result<(), String> {
    let text = serde_json::to_string_pretty(r).map_err(|e| e.to_string())?;
    write_durable(&recovery_path(), &text, || {})
}

pub fn clear_recovery() -> Result<(), String> {
    match std::fs::remove_file(recovery_path()) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("could not remove the hotel recovery record: {e}")),
    }
}

pub fn log(msg: &str) {
    pialite_common::logfile::append(&data_dir().join("guard.log"), 512 * 1024, msg);
    if std::env::var_os("PIALITE_CONSOLE").is_some() {
        eprintln!("{msg}");
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Tests that touch PIALITE_DATA take this lock (env vars are process-wide).
    pub static ENV_LOCK: Mutex<()> = Mutex::new(());

    pub fn temp_data(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pialite-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        std::env::set_var("PIALITE_DATA", &d);
        d
    }

    /// 0.9: features and DNS providers. Files from older versions keep
    /// everything they had (DNS via NextDNS, hotel login).
    #[test]
    fn features_and_dns_providers() {
        let old: Config = serde_json::from_str(r#"{"mode":"always","profile_id":"abc123"}"#).unwrap();
        let old = old.validate().unwrap();
        assert_eq!(old.features(), Features { dns: true, hotel: true }, "older file: what it had");
        assert_eq!(old.provider(), "nextdns");
        assert!(old.doh_path().starts_with("/abc123"));
        let new: Config = serde_json::from_str(r#"{"features":{"dns":false,"hotel":true}}"#).unwrap();
        assert_eq!(new.features(), Features { dns: false, hotel: true });
        assert_eq!(Config::default().features(), Features { dns: true, hotel: true }, "no choice recorded: as before 0.9");
        // presets
        let mut c = Config::default();
        for p in DNS_PRESETS {
            c.set_provider(p.id, None).unwrap();
            assert_eq!(c.doh_host, p.host);
            assert!(!c.doh_bootstrap.is_empty() && c.doh_bootstrap.iter().all(|ip| ip.parse::<std::net::IpAddr>().is_ok()));
            assert!(c.clone().validate().is_ok(), "{}", p.id);
        }
        c.set_provider("quad9", None).unwrap();
        assert_eq!((c.doh_host.as_str(), c.doh_path().as_str()), ("dns.quad9.net", "/dns-query"));
        assert!(c.set_provider("mullvad", None).is_err(), "not offered (service ended)");
        // custom
        let ips = vec!["203.0.113.5".to_string()];
        c.set_provider("custom", Some(("https://doh.example.net/q", &ips))).unwrap();
        assert_eq!((c.doh_host.as_str(), c.doh_path().as_str()), ("doh.example.net", "/q"));
        assert!(c.clone().validate().is_ok());
        assert!(c.set_provider("custom", Some(("https://doh.example.net/q", &[]))).is_err(), "needs an address");
        assert!(c.set_provider("custom", Some(("http://doh.example.net/q", &ips))).is_err(), "https only");
        assert!(c.set_provider("custom", Some(("https://bad host/q", &ips))).is_err());
        assert!(c.set_provider("custom", Some(("https://doh.example.net/a b", &ips))).is_err());
        let u = parse_server_url("https://Doh.Example.net:443").unwrap();
        assert_eq!((u.host.as_str(), u.path.as_str(), u.port, u.dot), ("doh.example.net", "/dns-query", 0, false));
        // a home server (Pi-hole behind dnsdist): DNS over TLS, own port, LAN address
        let u = parse_server_url("tls://pi.hole").unwrap();
        assert_eq!((u.host.as_str(), u.port, u.dot), ("pi.hole", 0, true));
        assert_eq!(parse_server_url("tls://pi.hole:8853").unwrap().port, 8853);
        assert_eq!(parse_server_url("tls://pi.hole:853").unwrap().port, 0, "the default port is stored as 0");
        assert_eq!(parse_server_url("https://pi.hole:8443/dns-query").unwrap().port, 8443);
        assert!(parse_server_url("tls://pi.hole/dns-query/x").is_err(), "tls:// has no path");
        assert!(parse_server_url("tls://pi.hole:0").is_err() && parse_server_url("tls://pi.hole:99999").is_err());
        assert!(parse_server_url("dot://pi.hole").is_err());
        let lan = vec!["192.168.1.2".to_string()];
        c.set_provider("custom", Some(("tls://pi.hole", &lan))).unwrap();
        assert!(c.dot() && c.port() == 853 && c.server_is_local() && c.custom_url() == "tls://pi.hole");
        assert!(c.clone().validate().is_ok());
        c.set_provider("custom", Some(("https://pi.hole:8443/dns-query", &lan))).unwrap();
        assert!(!c.dot() && c.port() == 8443 && c.custom_url() == "https://pi.hole:8443/dns-query");
        c.set_provider("custom", Some(("https://doh.example.net/q", &ips))).unwrap();
        assert!(!c.server_is_local() && c.port() == 443);
        c.doh_custom_ca = true;
        c.set_provider("quad9", None).unwrap();
        assert!(!c.doh_custom_ca && c.dot() && c.port() == 853, "a preset forgets the custom server's settings");
        assert!(
            is_local_ip("fd00::1".parse().unwrap()) && is_local_ip("10.1.2.3".parse().unwrap()) && !is_local_ip("9.9.9.9".parse().unwrap())
        );
        // a file naming an unknown provider is damaged (falls back like any damaged file)
        let bad: Config = serde_json::from_str(r#"{"dns_provider":"evil"}"#).unwrap();
        assert!(bad.validate().is_err());
    }

    #[test]
    fn doh_path_and_validation() {
        let mut c = Config { profile_id: "ab12cd".into(), device_name: "Sam's Laptop!".into(), ..Default::default() };
        assert_eq!(c.doh_path(), "/ab12cd/Sam-s-Laptop");
        c.device_name.clear();
        assert_eq!(c.doh_path(), "/ab12cd");
        assert!(valid_sid("S-1-5-21-111-222-333-1001"));
        assert!(!valid_sid("S-1-5"));
        assert!(!valid_sid("S-1-5-21-x"));
        assert!(!valid_sid("(A;;GA;;;WD)"));
        // v0.1 setting migrates
        let c: Config = serde_json::from_str::<Config>(r#"{"boot_block":true}"#).unwrap().validate().unwrap();
        assert_eq!(c.mode, BlockMode::Startup);
        assert!(!serde_json::to_string(&c).unwrap().contains("boot_block"));
        assert!(serde_json::from_str::<Config>(r#"{"profile_id":"../x"}"#).unwrap().validate().is_err());
    }

    #[test]
    fn hotel_recovery_record() {
        let _g = ENV_LOCK.lock().unwrap();
        let d = temp_data("recovery");
        assert_eq!(load_recovery(), RecoveryState::None);
        let r = Recovery::new(3, "on");
        save_recovery(&r).unwrap();
        assert_eq!(load_recovery(), RecoveryState::Pending(r));
        // normal settings saves don't touch it
        save(&Config::default()).unwrap();
        save(&Config::default()).unwrap();
        assert!(matches!(load_recovery(), RecoveryState::Pending(_)));
        std::fs::write(d.join("hotel-recovery.json"), "{ half").unwrap();
        assert!(matches!(load_recovery(), RecoveryState::Damaged(_)), "damaged = still outstanding");
        clear_recovery().unwrap();
        clear_recovery().unwrap();
        assert_eq!(load_recovery(), RecoveryState::None);
        let _ = std::fs::remove_dir_all(d);
    }

    /// The same cases the uninstaller's PowerShell reader is checked against
    /// (Phase5-Tests.ps1, quick checks): both must give the same answer.
    #[test]
    fn recovery_fixtures_agree() {
        let text = include_str!("../../tests/windows/scripts/recovery-fixtures.json");
        let v: serde_json::Value = serde_json::from_str(text).unwrap();
        let cases = v["cases"].as_array().unwrap();
        assert!(cases.len() >= 25);
        for c in cases {
            let name = c["name"].as_str().unwrap();
            let record = c["record"].as_str();
            let guard = c["guard"].as_str();
            let got = match decide(&record_from_text(record), &marker_from_text(guard)) {
                Verdict::None => "none".to_string(),
                Verdict::Restore(s) => format!("restore:{s}"),
                Verdict::Unknown(_) => "unknown".to_string(),
            };
            assert_eq!(got, c["expect"].as_str().unwrap(), "fixture '{name}'");
        }
    }

    #[test]
    fn recovery_record_written_as_version_1() {
        let t = serde_json::to_string(&Recovery::new(7, "on")).unwrap();
        assert_eq!(t, r#"{"version":1,"hotel":7,"saved_killswitch":"on"}"#);
        assert_eq!(parse_recovery(&t), Ok(Recovery::new(7, "on")));
    }

    #[test]
    fn corrupt_config_fails_closed() {
        let _g = ENV_LOCK.lock().unwrap();
        let d = temp_data("cfg");
        // fresh install
        assert!(matches!(load(|| false), Loaded::Fresh(_)));
        // save twice so a .bak exists
        let good = Config { mode: BlockMode::Always, profile_id: "abc123".into(), ..Default::default() };
        save(&good).unwrap();
        save(&good).unwrap();
        assert!(matches!(load(|| false), Loaded::Ok(ref c) if c.mode == BlockMode::Always));
        // damaged file -> last good copy
        std::fs::write(d.join("guard.json"), "{ truncated").unwrap();
        match load(|| false) {
            Loaded::Recovered(c, why) => {
                assert_eq!(c.mode, BlockMode::Always);
                assert!(why.contains("last good copy"));
            }
            _ => panic!("expected recovery"),
        }
        // missing file but a good backup -> backup (review N-03)
        std::fs::remove_file(d.join("guard.json")).unwrap();
        match load(|| false) {
            Loaded::Recovered(c, why) => {
                assert_eq!(c.mode, BlockMode::Always);
                assert!(why.contains("missing") && why.contains("last good copy"), "{why}");
            }
            _ => panic!("expected recovery from backup"),
        }
        // damaged and no backup, rules installed -> keep blocking, never "off"
        std::fs::write(d.join("guard.json"), "{ truncated").unwrap();
        std::fs::remove_file(d.join("guard.json.bak")).unwrap();
        match load(|| true) {
            Loaded::Recovered(c, _) => assert_eq!(c.mode, BlockMode::Startup),
            _ => panic!("expected recovery"),
        }
        // damaged, backup damaged too, no rules -> defaults but reported
        std::fs::write(d.join("guard.json.bak"), "garbage").unwrap();
        assert!(matches!(load(|| false), Loaded::Recovered(ref c, _) if c.mode == BlockMode::Off));
        // missing file, no backup, rules installed -> block stays (review N-03)
        std::fs::remove_file(d.join("guard.json")).unwrap();
        std::fs::remove_file(d.join("guard.json.bak")).unwrap();
        match load(|| true) {
            Loaded::Recovered(c, why) => {
                assert_eq!(c.mode, BlockMode::Startup);
                assert!(why.contains("missing") && why.contains("kept the block on"), "{why}");
            }
            _ => panic!("missing + rules present must not be a fresh install"),
        }
        // only no file + no backup + no rules is a fresh install
        assert!(matches!(load(|| false), Loaded::Fresh(ref c) if c.mode == BlockMode::Off));
        let _ = std::fs::remove_dir_all(d);
    }
}
