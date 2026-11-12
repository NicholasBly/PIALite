//! `setup` and `teardown`: the one install logic every installer runs - the
//! MSI (custom action), the .deb/.rpm scripts, install.sh, and the tray's
//! "Features" window - so all of them install exactly the features chosen.
//!
//! setup:    data folder (protected) -> settings (features, DNS provider,
//!           block mode, allowed user) -> guard service (or none) -> DNS
//!           hook-up -> start at sign-in -> install record (for the updater)
//! teardown: guard stopped -> block rules removed (checked) -> PIA's DNS and
//!           kill switch put back -> service and tasks removed -> data deleted

use crate::config::{self, Config, Features};
use crate::{firewall, pia, sys};
use pialite_common::status::BlockMode;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Optional parts, by the names installers use.
pub const FEATURES: &[(&str, &str)] = &[
    ("guard", "Network guard: background service with the kill switch (block internet until the VPN connects)"),
    ("dns", "Encrypted DNS: every lookup encrypted to the provider you pick (needs the guard)"),
    ("hotel", "Hotel Wi-Fi login: VPN off for a few minutes to get past a login page (needs the guard)"),
    ("autostart", "Start the PIA Lite tray when you sign in"),
    ("hidepia", "Windows: don't start PIA's own window at sign-in (saves ~160 MB; PIA Lite replaces it)"),
];

pub const DEFAULT_FEATURES: &[&str] = &["guard", "dns", "hotel", "autostart"];

#[derive(Default, Debug, Clone, PartialEq)]
pub struct Options {
    pub features: Option<Vec<String>>,
    pub dns: Option<String>,
    pub nextdns_id: Option<String>,
    pub doh_url: Option<String>,
    pub doh_ips: Option<Vec<String>>,
    pub doh_ca: Option<String>,
    pub mode: Option<BlockMode>,
    pub user: Option<String>,
    pub kind: Option<String>,
    pub product_code: Option<String>,
    pub interactive: bool,
}

/// `setup` arguments, as `--name value` or `--name=value`. An empty value
/// or "keep" means "not given" (the MSI passes every option, empty when the
/// user didn't choose). Unknown words are an error (a typo must not install
/// something other than what was asked).
pub fn parse_args(args: &[&str]) -> Result<Options, String> {
    const VALUED: &[&str] =
        &["--features", "--dns", "--nextdns-id", "--doh-url", "--doh-ips", "--doh-ca", "--mode", "--user", "--kind", "--product-code"];
    let mut pairs: Vec<(String, Option<String>)> = vec![];
    let mut i = 0;
    while i < args.len() {
        let a = args[i];
        if let Some((k, v)) = a.split_once('=').filter(|(k, _)| k.starts_with("--")) {
            pairs.push((k.to_string(), Some(v.to_string())));
        } else if VALUED.contains(&a) {
            let v = args.get(i + 1).ok_or(format!("{a} needs a value"))?;
            pairs.push((a.to_string(), Some(v.to_string())));
            i += 1;
        } else {
            pairs.push((a.to_string(), None));
        }
        i += 1;
    }
    let mut o = Options::default();
    for (k, v) in pairs {
        let v = v.map(|v| v.trim().to_string()).filter(|v| !v.is_empty() && v != "keep");
        match (k.as_str(), v) {
            ("--interactive" | "-i", None) => o.interactive = true,
            ("--keep", None) => {} // the default: anything not given stays as it is
            (k, None) if VALUED.contains(&k) => {}
            ("--features", Some(v)) => {
                // "none" alone = nothing optional; inside a list it is ignored
                // (the MSI builds "guard,dns,none")
                let list: Vec<String> = v.split(',').map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty() && s != "none").collect();
                if let Some(bad) = list.iter().find(|f| !FEATURES.iter().any(|(n, _)| n == f)) {
                    return Err(format!(
                        "unknown feature '{bad}' (known: {})",
                        FEATURES.iter().map(|(n, _)| *n).collect::<Vec<_>>().join(", ")
                    ));
                }
                o.features = Some(list);
            }
            ("--dns", Some(v)) => {
                let v = v.to_lowercase();
                if config::preset(&v).is_none() && v != "custom" {
                    return Err(format!("unknown DNS provider '{v}' (known: {}, custom)", config::preset_ids()));
                }
                o.dns = Some(v);
            }
            ("--nextdns-id", Some(v)) => {
                if !config::valid_profile(&v) {
                    return Err("that doesn't look like a NextDNS profile ID (letters and numbers, e.g. abc123)".into());
                }
                o.nextdns_id = Some(v);
            }
            ("--doh-url", Some(v)) => o.doh_url = Some(v),
            ("--doh-ca", Some(v)) => o.doh_ca = Some(v),
            ("--doh-ips", Some(v)) => o.doh_ips = Some(v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()),
            ("--mode", Some(v)) => o.mode = Some(BlockMode::parse(&v).ok_or(format!("unknown block mode '{v}' (off, startup, always)"))?),
            ("--user", Some(v)) => o.user = Some(v),
            ("--kind", Some(v)) => {
                if !KINDS.contains(&v.as_str()) {
                    return Err(format!("unknown install kind '{v}'"));
                }
                o.kind = Some(v);
            }
            ("--product-code", Some(v)) => o.product_code = Some(v),
            (other, _) => return Err(format!("unknown setup option '{other}' (see: pialite-guard help)")),
        }
    }
    Ok(o)
}

pub const KINDS: &[&str] = &["msi", "portable", "deb", "rpm", "tarball", "source"];

/// The kind of install a package says it is (a one-word file it ships).
fn packaged_kind() -> Option<String> {
    let dir = sys::exe_dir();
    [dir.join("install-kind"), dir.join("../share/pialite/install-kind"), PathBuf::from("/usr/share/pialite/install-kind")]
        .iter()
        .find_map(|p| std::fs::read_to_string(p).ok())
        .map(|t| t.trim().to_string())
        .filter(|k| KINDS.contains(&k.as_str()))
}

/// The features to install: as asked, else as installed before, else the
/// defaults. DNS and hotel login need the guard.
pub fn resolve_features(asked: Option<&[String]>, before: Option<&[String]>) -> Vec<String> {
    let mut f: Vec<String> = match (asked, before) {
        (Some(a), _) => a.to_vec(),
        (None, Some(b)) => b.to_vec(),
        (None, None) => DEFAULT_FEATURES.iter().map(|s| s.to_string()).collect(),
    };
    if !f.iter().any(|x| x == "guard") {
        f.retain(|x| x != "dns" && x != "hotel");
    }
    if !cfg!(windows) {
        f.retain(|x| x != "hidepia");
    }
    let order = |n: &String| FEATURES.iter().position(|(k, _)| k == n).unwrap_or(99);
    f.sort_by_key(order);
    f.dedup();
    f
}

fn has(f: &[String], name: &str) -> bool {
    f.iter().any(|x| x == name)
}

/// Apply the choices to the guard's settings. Pure, so it is tested.
pub fn apply_choices(cfg: &mut Config, o: &Options, features: &[String], fresh: bool) -> Result<(), String> {
    let guard = has(features, "guard");
    cfg.features = Some(Features { dns: has(features, "dns"), hotel: has(features, "hotel") });
    if o.dns.is_none() && fresh {
        // a first install without a choice: a provider that needs no account
        cfg.set_provider("quad9", None)?;
    }
    if let Some(p) = &o.dns {
        if p == "custom" {
            let url = o.doh_url.as_deref().ok_or("--dns custom needs --doh-url https://... (or tls://...) and --doh-ips")?;
            let ips = o.doh_ips.clone().unwrap_or_default();
            cfg.set_provider("custom", Some((url, &ips)))?;
            // the CA file itself is copied by setup(); here only the choice
            cfg.doh_custom_ca = o.doh_ca.is_some();
        } else {
            cfg.set_provider(p, None)?;
        }
    }
    if let Some(id) = &o.nextdns_id {
        if !id.is_empty() {
            cfg.profile_id = id.clone();
        }
    }
    if cfg.device_name.is_empty() {
        cfg.device_name = device_name();
    }
    if has(features, "dns") && cfg.provider() == "nextdns" && cfg.profile_id.is_empty() {
        return Err(
            "NextDNS needs your profile ID (the code on my.nextdns.io): --nextdns-id ID - or pick another provider with --dns".into()
        );
    }
    cfg.mode = match (guard, o.mode) {
        (false, _) => BlockMode::Off,
        (true, Some(m)) => m,
        (true, None) if fresh => BlockMode::Startup,
        (true, None) => cfg.mode,
    };
    if let Some(u) = &o.user {
        add_user(cfg, u)?;
    }
    *cfg = cfg.clone().validate()?;
    Ok(())
}

fn add_user(cfg: &mut Config, u: &str) -> Result<(), String> {
    if let Ok(uid) = u.parse::<u32>() {
        if !cfg.allowed_uids.contains(&uid) {
            cfg.allowed_uids.push(uid);
        }
    } else if config::valid_sid(u) {
        if !cfg.allowed_sids.iter().any(|s| s.eq_ignore_ascii_case(u)) {
            cfg.allowed_sids.push(u.to_string());
        }
    } else {
        return Err(format!("--user: '{u}' is neither a Windows account ID (S-1-5-...) nor a Linux user id"));
    }
    Ok(())
}

/// This computer's name as NextDNS shows it in its logs (letters, digits, '-').
fn device_name() -> String {
    #[cfg(windows)]
    let n = std::env::var("COMPUTERNAME").unwrap_or_default();
    #[cfg(not(windows))]
    let n = std::fs::read_to_string("/etc/hostname").unwrap_or_default();
    let n: String = n.trim().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).take(32).collect();
    if n.is_empty() {
        "PIA-Lite".into()
    } else {
        n
    }
}

/// Who should be allowed to use the tray with the guard: as given, else the
/// user who ran sudo/pkexec (Linux), else the account running setup.
fn default_user() -> Option<String> {
    #[cfg(windows)]
    {
        let (ok, out) = sys::run("whoami", &["/user", "/fo", "csv", "/nh"]).ok()?;
        let sid = out.trim().rsplit(',').next()?.trim_matches('"').to_string();
        // not SYSTEM (the MSI passes the installing user itself)
        (ok && config::valid_sid(&sid) && sid != "S-1-5-18").then_some(sid)
    }
    #[cfg(not(windows))]
    {
        sys::invoking_uid().map(|u| u.to_string())
    }
}

struct Report {
    lines: Vec<String>,
    warnings: Vec<String>,
}

impl Report {
    fn ok(&mut self, m: impl Into<String>) {
        let m = m.into();
        println!("  ok  {m}");
        config::log(&format!("setup: {m}"));
        self.lines.push(m);
    }
    fn warn(&mut self, m: impl Into<String>) {
        let m = m.into();
        println!("  !!  {m}");
        config::log(&format!("setup WARNING: {m}"));
        self.warnings.push(m);
    }
}

fn sibling(name: &str) -> PathBuf {
    sys::exe_dir().join(if cfg!(windows) { format!("{name}.exe") } else { name.to_string() })
}

/// A service running as SYSTEM/root must only run a program ordinary users
/// can't replace.
fn check_program_location(exe: &Path, kind: &str) -> Result<(), String> {
    #[cfg(windows)]
    {
        let dir = exe.parent().ok_or("no program folder")?;
        let pf: Vec<String> = ["ProgramFiles", "ProgramW6432", "ProgramFiles(x86)"]
            .iter()
            .filter_map(|v| std::env::var(v).ok())
            .map(|p| p.trim_end_matches('\\').to_lowercase() + "\\")
            .collect();
        let d = dir.display().to_string().to_lowercase() + "\\";
        if pf.iter().any(|p| d.starts_with(p)) {
            return Ok(());
        }
        if kind == "msi" {
            // a custom MSI folder: give it Program Files' protection
            let ds = dir.display().to_string();
            sys::run(
                "icacls",
                &[
                    &ds,
                    "/inheritance:r",
                    "/grant:r",
                    "*S-1-5-18:(OI)(CI)F",
                    "*S-1-5-32-544:(OI)(CI)F",
                    "*S-1-5-32-545:(OI)(CI)RX",
                    "/T",
                    "/C",
                    "/Q",
                ],
            )
            .and_then(|(ok, out)| if ok { Ok(()) } else { Err(out.trim().to_string()) })
            .map_err(|e| format!("could not protect {ds}: {e}"))?;
            return Ok(());
        }
        Err(format!(
            "the guard service must run from Program Files, not {} (ordinary users could swap the program there) - install with the MSI to get the guard",
            dir.display()
        ))
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = kind;
        let real = std::fs::canonicalize(exe).map_err(|e| format!("{}: {e}", exe.display()))?;
        let mut p = real.as_path();
        loop {
            let m = std::fs::metadata(p).map_err(|e| format!("{}: {e}", p.display()))?;
            if m.uid() != 0 || m.mode() & 0o022 != 0 {
                return Err(format!(
                    "the guard service must run from a folder only root can change - {} isn't (install with the .deb/.rpm or install.sh to get the guard)",
                    p.display()
                ));
            }
            match p.parent() {
                Some(up) => p = up,
                None => return Ok(()),
            }
        }
    }
}

fn ask(question: &str, default: &str) -> String {
    use std::io::Write;
    print!("{question} [{default}]: ");
    let _ = std::io::stdout().flush();
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line);
    let a = line.trim();
    if a.is_empty() {
        default.to_string()
    } else {
        a.to_string()
    }
}

fn ask_yes(question: &str, default: bool) -> bool {
    let hint = if default { "Y/n" } else { "y/N" };
    loop {
        let a = ask(question, hint).to_lowercase();
        match a.as_str() {
            "y/n" => return default,
            "y" | "yes" => return true,
            "n" | "no" => return false,
            _ => println!("  please answer y or n"),
        }
    }
}

/// Terminal questions (Linux install.sh, or `sudo pialite-guard setup -i`).
fn interview(o: &mut Options, cfg: &Config, before: Option<&[String]>) {
    let had = resolve_features(None, before);
    println!("\nPIA Lite setup - pick what you want (Enter keeps the answer in brackets).\n");
    let mut f = vec![];
    for (name, what) in FEATURES {
        if *name == "hidepia" && !cfg!(windows) {
            continue;
        }
        if (*name == "dns" || *name == "hotel") && !f.iter().any(|x| x == "guard") {
            continue;
        }
        println!("{what}");
        if ask_yes(&format!("  install '{name}'?"), has(&had, name)) {
            f.push(name.to_string());
        }
    }
    if has(&f, "dns") {
        println!("\nEncrypted DNS provider:");
        for p in config::DNS_PRESETS {
            println!("  {:<11} {}", p.id, p.name);
        }
        println!("  {:<11} your own server, e.g. a Pi-hole at home (DNS over HTTPS or TLS)", "custom");
        loop {
            let p = ask("  provider", cfg.provider()).to_lowercase();
            if p == "custom" {
                o.doh_url = Some(ask("  server (https://host/dns-query or tls://host)", ""));
                o.doh_ips = Some(
                    ask("  its IP addresses (comma separated)", "")
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect(),
                );
                let ca = ask("  its own certificate authority file (PEM; Enter = a public certificate)", "");
                o.doh_ca = Some(ca).filter(|c| !c.is_empty());
            } else if config::preset(&p).is_none() {
                println!("  unknown provider");
                continue;
            }
            if p == "nextdns" {
                loop {
                    let id = ask("  your NextDNS profile ID (my.nextdns.io)", &cfg.profile_id);
                    if config::valid_profile(&id) {
                        o.nextdns_id = Some(id);
                        break;
                    }
                    println!("  letters and numbers only, e.g. abc123");
                }
            }
            o.dns = Some(p);
            break;
        }
    }
    if has(&f, "guard") {
        println!("\nBlock internet (kill switch):");
        println!("  off      never");
        println!("  startup  from power-on until the VPN connects, then PIA's own kill switch");
        println!("  always   whenever the VPN is not connected");
        loop {
            let def = if before.is_some() { cfg.mode.as_str() } else { "startup" };
            if let Some(m) = BlockMode::parse(&ask("  mode", def)) {
                o.mode = Some(m);
                break;
            }
            println!("  off, startup or always");
        }
    }
    o.features = Some(f);
}

pub fn setup(mut o: Options) -> Result<(), String> {
    if !sys::is_admin() {
        return Err(if cfg!(windows) {
            "setup needs an administrator (right-click > Run as administrator)".into()
        } else {
            "setup needs root: sudo pialite-guard setup".into()
        });
    }
    let before = sys::read_record();
    let mut rep = Report { lines: vec![], warnings: vec![] };
    println!("PIA Lite {} setup", env!("CARGO_PKG_VERSION"));
    sys::protect_data_dir()?;
    let fresh = !config::data_dir().join("guard.json").is_file();
    let mut cfg = config::load(|| firewall::installed().unwrap_or(true)).config().clone();
    if o.interactive {
        interview(&mut o, &cfg, before.as_ref().map(|r| r.features.as_slice()));
    }
    let features = resolve_features(o.features.as_deref(), before.as_ref().map(|r| r.features.as_slice()));
    if o.user.is_none() {
        o.user = default_user();
    }
    apply_choices(&mut cfg, &o, &features, fresh)?;
    let guard = has(&features, "guard");
    let kind = o
        .kind
        .clone()
        .or(before.as_ref().map(|r| r.kind.clone()).filter(|k| !k.is_empty()))
        .or_else(packaged_kind)
        .unwrap_or_else(|| "source".into());
    let guard_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    if guard {
        check_program_location(&guard_exe, &kind)?;
        #[cfg(not(windows))]
        {
            if cfg.mode != BlockMode::Off && pia::engine_gid().is_none() {
                return Err("PIA is not installed (no 'piavpn' group) - the kill switch would block PIA itself. Install PIA first, or use --mode off".into());
            }
            if !["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"].iter().any(|p| Path::new(p).is_file()) {
                return Err("the guard needs nftables: install the 'nftables' package first".into());
            }
            ensure_group(&mut rep);
        }
    }
    if let Some(ca) = &o.doh_ca {
        install_ca_file(Path::new(ca))?;
    }
    config::save(&cfg)?;
    rep.ok(format!("settings saved: {}", describe(&cfg, &features)));

    if guard {
        sys::stop_service()?; // a running guard re-reads everything when it starts
        sys::register_service(&guard_exe)?;
        sys::start_service()?;
        match sys::wait_for_guard(Duration::from_secs(30)) {
            Ok(st) => {
                rep.ok(format!("guard service running (version {})", st.version));
                if st.mode != BlockMode::Off && !st.armed {
                    rep.warn(format!(
                        "the internet block is NOT in place yet: {}",
                        if st.fw_error.is_empty() { "see the guard log" } else { &st.fw_error }
                    ));
                }
            }
            Err(e) => rep.warn(e),
        }
    } else if sys::service_installed() {
        sys::remove_service()?;
        firewall::uninstall()?;
        let _ = firewall::dns_capture(false);
        rep.ok("guard service removed (not chosen)");
    }

    hook_up_dns(&cfg, has(&features, "dns"), &mut rep);
    if has(&features, "dns") {
        check_dns_conflicts(&cfg, &mut rep);
    }

    let tray = sibling("pialite-tray");
    match sys::set_tray_autostart(has(&features, "autostart"), &tray) {
        Ok(()) if has(&features, "autostart") => rep.ok("the tray starts when you sign in"),
        Ok(()) => {}
        Err(e) => rep.warn(format!("start at sign-in: {e}")),
    }
    #[cfg_attr(not(windows), allow(unused_mut))]
    let mut pia_task = before.as_ref().map(|r| r.pia_task_disabled).unwrap_or(false);
    #[cfg(windows)]
    {
        match (has(&features, "hidepia"), pia_task) {
            (true, false) => match set_pia_task(false) {
                Ok(true) => {
                    pia_task = true;
                    rep.ok("PIA's own window no longer starts at sign-in");
                }
                Ok(false) => {}
                Err(e) => rep.warn(format!("PIA's startup task: {e}")),
            },
            (false, true) => match set_pia_task(true) {
                Ok(_) => {
                    pia_task = false;
                    rep.ok("PIA's own window starts at sign-in again");
                }
                Err(e) => rep.warn(format!("PIA's startup task: {e}")),
            },
            _ => {}
        }
    }
    sys::write_record(&sys::InstallRecord {
        kind,
        version: env!("CARGO_PKG_VERSION").into(),
        features: features.clone(),
        dir: sys::exe_dir().display().to_string(),
        product_code: o.product_code.clone().or(before.map(|b| b.product_code).filter(|p| !p.is_empty())).unwrap_or_default(),
        pia_task_disabled: pia_task,
    })?;
    if !pia_present() {
        rep.warn("Private Internet Access doesn't seem to be installed - PIA Lite needs it (privateinternetaccess.com)");
    }
    println!();
    if rep.warnings.is_empty() {
        println!("Done - PIA Lite is set up.");
    } else {
        println!("Done, with {} warning(s) above (details in the guard log).", rep.warnings.len());
    }
    Ok(())
}

fn pia_present() -> bool {
    pialite_common::piactl::exe().is_file()
}

fn describe(cfg: &Config, features: &[String]) -> String {
    let mut parts = vec![];
    if has(features, "guard") {
        parts.push(format!("guard on, block mode {}", cfg.mode.as_str()));
    } else {
        parts.push("tray only (no guard)".into());
    }
    if has(features, "dns") {
        parts.push(format!("encrypted DNS via {}", config::preset(cfg.provider()).map(|p| p.name).unwrap_or("your own DoH server")));
    }
    if has(features, "hotel") {
        parts.push("hotel login".into());
    }
    parts.join(", ")
}

/// Linux: members of group "pialite" may use the tray with the guard.
#[cfg(not(windows))]
fn ensure_group(rep: &mut Report) {
    if pia::group_id(crate::ipc::USERS_GROUP).is_none() {
        match sys::run("groupadd", &["--system", crate::ipc::USERS_GROUP]) {
            Ok((true, _)) => rep.ok(format!("group '{}' created (its members may use the tray with the guard)", crate::ipc::USERS_GROUP)),
            Ok((false, e)) | Err(e) => rep.warn(format!("could not create group '{}': {}", crate::ipc::USERS_GROUP, e.trim())),
        }
    }
    if let Some(uid) = sys::invoking_uid() {
        if let Some(name) = crate::ipc::user_name(uid) {
            if let Ok((true, _)) = sys::run("usermod", &["-aG", crate::ipc::USERS_GROUP, &name]) {
                rep.ok(format!("user '{name}' added to group '{}'", crate::ipc::USERS_GROUP));
            }
        }
    }
}

/// Windows: PIA's DNS setting points at the proxy (127.0.0.1) - the
/// previous value is saved first and put back when encrypted DNS is turned
/// off. Linux needs nothing here: the guard redirects plain DNS itself.
fn hook_up_dns(cfg: &Config, dns: bool, rep: &mut Report) {
    if !cfg!(windows) {
        if dns {
            rep.ok("encrypted DNS: the guard sends every lookup to the proxy (nftables redirect)");
        }
        return;
    }
    if dns {
        // check the provider answers before relying on it
        if let Err(e) = test_provider(cfg) {
            if cfg.provider() == "custom" {
                rep.warn(format!("your DoH server didn't answer ({e}) - PIA's DNS was NOT changed; fix it and run setup again"));
                return;
            }
            rep.warn(format!("{} didn't answer right now ({e}) - continuing (it is retried once the VPN is connected)", cfg.provider()));
        }
        if !pia_present() {
            rep.warn("PIA not found - its DNS setting can't be pointed at the guard yet; run setup again after installing PIA");
            return;
        }
        match pia::read_override_dns() {
            Ok(v) if pia::dns_is_proxy(&v) => rep.ok("PIA already sends DNS to the guard"),
            Ok(v) => {
                let backup = config::data_dir().join(DNS_BACKUP);
                if !backup.is_file() {
                    if let Err(e) = std::fs::write(&backup, v.to_string()) {
                        rep.warn(format!("could not save PIA's DNS setting ({e}) - not changing it"));
                        return;
                    }
                }
                match pia::set_override_dns(&serde_json::json!([pia::PROXY_DNS])) {
                    Ok(()) => rep.ok("PIA's DNS now points at the guard (127.0.0.1) - applies from the next connection"),
                    Err(e) => rep.warn(format!("PIA's DNS setting could not be changed: {e}")),
                }
            }
            Err(e) => rep.warn(format!("PIA's settings could not be read ({e}) - is PIA's service running?")),
        }
        pause_nextdns_app(rep);
    } else {
        restore_pia_dns(rep);
        resume_nextdns_app(rep);
    }
}

pub const DNS_BACKUP: &str = "pia-dns-before.json";

/// Things that would make lookups miss the guard, said plainly (setup never
/// changes another program or an adapter by itself - except pausing the
/// NextDNS app, as before; `adapter-dns --reset` is the user's choice).
fn check_dns_conflicts(cfg: &Config, rep: &mut Report) {
    if cfg.provider() == "custom" && cfg.server_is_local() {
        match pia::read_settings() {
            Ok(s) if !s.allow_lan => rep.warn(format!(
                "your DNS server ({}) is on your home network, but PIA's 'Allow LAN' is off - while the VPN is connected PIA                  blocks it and lookups fail. Turn on Settings > Network > Allow LAN in PIA",
                cfg.custom_url()
            )),
            _ => rep.ok(format!("home DNS server {} (reached over your network, encrypted)", cfg.custom_url())),
        }
    }
    match sys::dns_setup() {
        Ok(d) => {
            let w = sys::dns_conflicts(&d);
            if w.is_empty() {
                rep.ok("no other DNS settings or programs found that would bypass PIA Lite");
            }
            for x in w {
                rep.warn(x);
            }
        }
        Err(e) => rep.warn(format!("could not check the network adapters' DNS settings: {e}")),
    }
}

/// `adapter-dns [--json] [--reset]`
pub fn adapter_dns(json: bool, reset: bool) -> Result<(), String> {
    let d = sys::dns_setup()?;
    if json {
        println!("{}", serde_json::to_string_pretty(&d).map_err(|e| e.to_string())?);
        return Ok(());
    }
    if cfg!(windows) {
        println!("Network adapters (connected, not PIA's):");
        for a in &d.adapters {
            let servers: Vec<&str> = a.v4.iter().chain(a.v6.iter()).map(String::as_str).collect();
            println!(
                "  {:<24} {}{}",
                a.alias,
                if a.manual() { format!("set by hand: {}", servers.join(", ")) } else { "automatic (DHCP)".into() },
                if a.doh && a.manual() { " + Windows DNS over HTTPS" } else { "" }
            );
        }
    }
    println!("DNS port 53 held by: {}", if d.port53.is_empty() { "nothing".into() } else { d.port53.join(", ") });
    if !d.dns_apps.is_empty() {
        println!("DNS programs: {}", d.dns_apps.join(", "));
    }
    let w = sys::dns_conflicts(&d);
    if w.is_empty() {
        println!("Nothing found that would bypass PIA Lite's encrypted DNS.");
    }
    for x in &w {
        println!("NOTE: {x}");
    }
    if reset {
        if !cfg!(windows) {
            return Err("--reset is for Windows adapters".into());
        }
        if !sys::is_admin() {
            return Err("--reset needs an administrator".into());
        }
        sys::protect_data_dir()?;
        let done = sys::reset_adapter_dns(&d)?;
        if done.is_empty() {
            println!("No adapter has DNS set by hand - nothing to reset.");
        } else {
            println!("Set back to automatic: {} (the old settings are saved and come back if PIA Lite is removed)", done.join(", "));
        }
    }
    Ok(())
}

/// Copy a home server's certificate authority (PEM) into the admin-only data
/// folder, where the guard reads it. Checked first.
pub fn install_ca_file(src: &Path) -> Result<(), String> {
    let pem = std::fs::read(src).map_err(|e| format!("{}: {e}", src.display()))?;
    let n = config::check_ca_pem(&pem)?;
    let dst = config::custom_ca_path();
    let tmp = dst.with_extension("tmp");
    std::fs::write(&tmp, &pem)
        .and_then(|_| std::fs::rename(&tmp, &dst))
        .map_err(|e| format!("{}: {e} (run as administrator / root)", dst.display()))?;
    println!("  ok  certificate authority saved ({n} certificate(s)) - only it is trusted for your server");
    Ok(())
}

fn test_provider(cfg: &Config) -> Result<(), String> {
    use crate::doh::Resolve;
    let d = crate::doh::Doh::from_config(cfg)?;
    let a = d.resolve(&crate::dns::build_query(0x4242, "example.com", 1)?)?;
    match crate::dns::summary(&a) {
        Some((0, n)) if n > 0 => Ok(()),
        other => Err(format!("unexpected answer {other:?}")),
    }
}

fn restore_pia_dns(rep: &mut Report) {
    if !cfg!(windows) {
        return;
    }
    let backup = config::data_dir().join(DNS_BACKUP);
    let saved = std::fs::read_to_string(&backup).ok().and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok());
    let current = pia::read_override_dns().ok();
    if !current.as_ref().is_some_and(pia::dns_is_proxy) {
        let _ = std::fs::remove_file(&backup);
        return; // not pointed at the guard: leave PIA's choice alone
    }
    // the value from before PIA Lite; if it was lost, PIA's own DNS
    let back = saved.filter(|v| !pia::dns_is_proxy(v)).unwrap_or_else(|| "pia".into());
    match pia::set_override_dns(&back) {
        Ok(()) => {
            let _ = std::fs::remove_file(&backup);
            rep.ok(format!("PIA's DNS setting put back ({back})"));
        }
        Err(e) => rep.warn(format!("PIA's DNS still points at 127.0.0.1 ({e}) - set DNS to 'PIA DNS' in PIA's settings, or lookups fail")),
    }
}

const NEXTDNS_SVC: &str = "NextDNS";
const NEXTDNS_BACKUP: &str = "nextdns-before.txt";

/// Two DNS stacks fight: the NextDNS Windows app is paused (stopped and
/// disabled, not removed) while the guard does encrypted DNS.
fn pause_nextdns_app(rep: &mut Report) {
    #[cfg(windows)]
    {
        let Ok((true, qc)) = sys::run("sc.exe", &["qc", NEXTDNS_SVC]) else { return };
        let start = qc
            .lines()
            .find(|l| l.contains("START_TYPE"))
            .map(|l| l.split_whitespace().last().unwrap_or("").to_string())
            .unwrap_or_default();
        if start == "DISABLED" {
            return;
        }
        let backup = config::data_dir().join(NEXTDNS_BACKUP);
        if !backup.is_file() && std::fs::write(&backup, &start).is_err() {
            rep.warn("could not note the NextDNS app's start type - leaving it alone");
            return;
        }
        let _ = sys::run("sc.exe", &["stop", NEXTDNS_SVC]);
        match sys::run("sc.exe", &["config", NEXTDNS_SVC, "start=", "disabled"]) {
            Ok((true, _)) => rep.ok("NextDNS app paused (stopped and disabled, not removed) - the guard does encrypted DNS now"),
            _ => rep.warn("could not pause the NextDNS app - two DNS programs may fight; stop 'NextDNS' in services.msc"),
        }
    }
    #[cfg(not(windows))]
    let _ = (rep, NEXTDNS_SVC);
}

fn resume_nextdns_app(rep: &mut Report) {
    let backup = config::data_dir().join(NEXTDNS_BACKUP);
    let Ok(start) = std::fs::read_to_string(&backup) else { return };
    #[cfg(windows)]
    {
        let start = match start.trim() {
            "AUTO_START" | "(DELAYED)" => "auto",
            "DEMAND_START" => "demand",
            _ => "auto",
        };
        if sys::run("sc.exe", &["qc", NEXTDNS_SVC]).map(|(ok, _)| ok).unwrap_or(false) {
            let _ = sys::run("sc.exe", &["config", NEXTDNS_SVC, "start=", start]);
            let _ = sys::run("sc.exe", &["start", NEXTDNS_SVC]);
            rep.ok("NextDNS app turned back on");
        }
    }
    #[cfg(not(windows))]
    let _ = (start, &rep);
    let _ = std::fs::remove_file(&backup);
}

/// Windows: PIA's own "Start PIA First" sign-in task. Returns whether it
/// was changed (false when it doesn't exist or already was so).
#[cfg(windows)]
fn set_pia_task(enable: bool) -> Result<bool, String> {
    let name = "Start PIA First";
    let (ok, out) = sys::run("schtasks", &["/Query", "/TN", name, "/FO", "CSV", "/NH"])?;
    if !ok {
        return Ok(false);
    }
    let disabled = out.contains("Disabled");
    if disabled != enable {
        return Ok(false);
    }
    let (ok, out) = sys::run("schtasks", &["/Change", "/TN", name, if enable { "/ENABLE" } else { "/DISABLE" }])?;
    if ok {
        Ok(true)
    } else {
        Err(out.trim().to_string())
    }
}

/// Undo everything setup did. `keep_config`: keep settings + log (upgrades
/// that replace the program, or "remove but keep my choices").
pub fn teardown(keep_config: bool) -> Result<(), String> {
    if !sys::is_admin() {
        return Err(if cfg!(windows) {
            "teardown needs an administrator".into()
        } else {
            "teardown needs root: sudo pialite-guard teardown".into()
        });
    }
    let mut rep = Report { lines: vec![], warnings: vec![] };
    println!("Removing PIA Lite's system parts...");
    let record = sys::read_record();
    // 1. the guard first, so it can't put rules back while they're removed
    let was_running = sys::service_running();
    sys::stop_service()?;
    if was_running {
        rep.ok("guard service stopped");
    }
    // 2. the block, checked
    firewall::uninstall()?;
    let _ = firewall::reset_open();
    let _ = firewall::dns_capture(false);
    match firewall::installed() {
        Ok(false) => rep.ok("internet block rules removed (checked)"),
        Ok(true) => return Err("block rules are STILL in place - run `pialite-guard unlock` as admin, then teardown again".into()),
        Err(e) => return Err(format!("could not check the block rules were removed ({e}) - not continuing")),
    }
    // 3. PIA as it was: DNS, kill switch (an unfinished hotel login), NextDNS app, startup task
    restore_pia_dns(&mut rep);
    match sys::restore_adapter_dns() {
        Ok(done) if !done.is_empty() => rep.ok(format!("DNS set by hand put back on: {}", done.join(", "))),
        Ok(_) => {}
        Err(e) => rep.warn(format!("could not put the adapters' own DNS settings back: {e}")),
    }
    resume_nextdns_app(&mut rep);
    let cfg = config::load(|| false).config().clone();
    let saved = match config::load_recovery() {
        config::RecoveryState::Pending(r) => Some(r.saved_killswitch),
        config::RecoveryState::Damaged(why) => {
            rep.warn(format!("the hotel-login record is damaged ({why}) - check PIA's kill switch setting yourself"));
            None
        }
        config::RecoveryState::None => {
            (cfg.hotel_active && !cfg.hotel_saved_killswitch.is_empty()).then(|| cfg.hotel_saved_killswitch.clone())
        }
    };
    if let Some(ks) = saved {
        match pia::set_killswitch(&ks) {
            Ok(()) => {
                let _ = config::clear_recovery();
                rep.ok(format!("PIA's kill switch put back to '{ks}' (a hotel login was unfinished)"));
            }
            Err(e) => rep.warn(format!("PIA's kill switch could not be put back to '{ks}': {e} - set it in PIA's settings")),
        }
    }
    #[cfg(windows)]
    if record.as_ref().is_some_and(|r| r.pia_task_disabled) {
        match set_pia_task(true) {
            Ok(_) => rep.ok("PIA's own window starts at sign-in again"),
            Err(e) => rep.warn(format!("PIA's startup task: {e}")),
        }
    }
    let _ = sys::set_tray_autostart(false, &sibling("pialite-tray"));
    // 4. the service itself
    sys::remove_service()?;
    rep.ok("guard service removed");
    // 5. data
    if !keep_config {
        let dir = config::data_dir();
        match std::fs::remove_dir_all(&dir) {
            // printed only: logging would create the folder (and its log) again
            Ok(()) => println!("  ok  deleted {}", dir.display()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => rep.warn(format!("could not delete {} ({e}) - delete it later", dir.display())),
        }
    } else if record.is_some() {
        let _ = std::fs::remove_file(sys::record_path());
    }
    println!("Done{}.", if rep.warnings.is_empty() { "" } else { " (see the warnings above)" });
    Ok(())
}

/// What is installed, for `pialite-guard features` and the tray.
pub fn features_report(json: bool) -> Result<(), String> {
    let rec = sys::read_record();
    let cfg = config::load(|| false).config().clone();
    let f = rec.as_ref().map(|r| r.features.clone()).unwrap_or_default();
    if json {
        println!(
            "{}",
            serde_json::json!({
                "installed": rec.is_some(),
                "kind": rec.as_ref().map(|r| r.kind.clone()),
                "version": rec.as_ref().map(|r| r.version.clone()),
                "features": f,
                "dns_provider": cfg.provider(),
                "mode": cfg.mode.as_str(),
                "service_installed": sys::service_installed(),
                "service_running": sys::service_running(),
            })
        );
        return Ok(());
    }
    match &rec {
        None => println!("No install record (not set up with an installer, or set up by a version before 0.9)."),
        Some(r) => println!("Installed as: {} {} in {}", r.kind, r.version, r.dir),
    }
    for (name, what) in FEATURES {
        if *name == "hidepia" && !cfg!(windows) {
            continue;
        }
        println!("  [{}] {name:<9} {what}", if has(&f, name) { "x" } else { " " });
    }
    if has(&f, "dns") {
        println!("DNS provider: {}", config::preset(cfg.provider()).map(|p| p.name).unwrap_or("custom"));
    }
    println!(
        "Guard service: {}",
        match (sys::service_installed(), sys::service_running()) {
            (false, _) => "not installed",
            (true, true) => "running",
            (true, false) => "installed, NOT running",
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn dns_conflicts_are_found_and_explained() {
        // what PowerShell writes for one Wi-Fi adapter with NextDNS typed in (+ DoH), YogaDNS running
        let one = r#"{"adapters":{"alias":"Wi-Fi","index":12,"description":"Intel Wi-Fi","v4":"45.90.28.0","v6":[],"doh":true},"port53":"127.0.0.1|YogaDNS","dns_apps":"YogaDNS|YogaDNS Service|Running","resolved_dot":false}"#;
        let d = sys::parse_dns_setup(one).unwrap();
        assert_eq!(d.adapters.len(), 1);
        assert_eq!(d.adapters[0].v4, vec!["45.90.28.0"]);
        let w = sys::dns_conflicts(&d);
        assert_eq!(w.len(), 3, "{w:?}");
        assert!(w[0].contains("'Wi-Fi' has DNS set by hand (45.90.28.0) with Windows' own DNS over HTTPS"));
        assert!(w[1].contains("port 53") && w[1].contains("YogaDNS"));
        assert!(w[2].starts_with("YogaDNS Service is running"));
        // automatic DNS, the guard on port 53, the NextDNS app paused: nothing to say
        let fine = r#"{"adapters":[{"alias":"Ethernet","index":3,"description":"x","v4":[],"v6":[],"doh":false}],"port53":["127.0.0.1|pialite-guard"],"dns_apps":["NextDNS|NextDNS|Stopped"],"resolved_dot":false}"#;
        assert!(sys::dns_conflicts(&sys::parse_dns_setup(fine).unwrap()).is_empty());
        let empty = r#"{"adapters":[],"port53":[],"dns_apps":[],"resolved_dot":true}"#;
        assert!(sys::dns_conflicts(&sys::parse_dns_setup(empty).unwrap())[0].contains("systemd-resolved"));
        assert!(sys::parse_dns_setup("nope").is_err());
    }

    #[test]
    fn arguments() {
        let o = parse_args(&["--features", "guard,dns", "--dns", "quad9", "--mode", "always", "--kind", "msi", "--user", "1000"]).unwrap();
        assert_eq!(o.features, Some(s(&["guard", "dns"])));
        assert_eq!(o.dns.as_deref(), Some("quad9"));
        assert_eq!(o.mode, Some(BlockMode::Always));
        assert_eq!(o.user.as_deref(), Some("1000"));
        assert_eq!(parse_args(&["--features", "none"]).unwrap().features, Some(vec![]));
        // the MSI's command line: --name=value, empty = not chosen, "keep" = keep
        let m = parse_args(&[
            "--kind=msi",
            "--features=guard,hotel,none",
            "--dns=",
            "--nextdns-id=",
            "--mode=keep",
            "--user=S-1-5-21-1-2-3-1001",
            "--product-code={ABC}",
        ])
        .unwrap();
        assert_eq!(m.features, Some(s(&["guard", "hotel"])));
        assert_eq!((m.dns, m.nextdns_id, m.mode), (None, None, None));
        assert_eq!(m.kind.as_deref(), Some("msi"));
        assert_eq!(m.product_code.as_deref(), Some("{ABC}"));
        assert!(parse_args(&["--kind=zip"]).is_err());
        let h = parse_args(&["--dns", "custom", "--doh-url", "tls://pi.hole", "--doh-ips", "192.168.1.2", "--doh-ca", "ca.pem"]).unwrap();
        assert_eq!((h.doh_url.as_deref(), h.doh_ca.as_deref()), (Some("tls://pi.hole"), Some("ca.pem")));
        assert!(parse_args(&["--features", "guard,dsn"]).unwrap_err().contains("unknown feature 'dsn'"), "a typo is refused");
        assert!(parse_args(&["--dns", "opendns"]).is_err());
        assert!(parse_args(&["--mode"]).is_err(), "a missing value");
        assert!(parse_args(&["--nextdns-id", "ab c"]).is_err());
        assert!(parse_args(&["--frobnicate"]).is_err());
        assert_eq!(parse_args(&["--user", ""]).unwrap().user, None, "the MSI may pass an empty user");
    }

    #[test]
    fn feature_rules() {
        assert_eq!(resolve_features(None, None), s(DEFAULT_FEATURES), "first install: the defaults");
        let before = s(&["guard", "hotel"]);
        assert_eq!(resolve_features(None, Some(&before)), before, "an upgrade keeps what was chosen");
        assert_eq!(resolve_features(Some(&s(&["dns", "hotel", "autostart"])), None), s(&["autostart"]), "DNS and hotel need the guard");
        assert_eq!(resolve_features(Some(&s(&["hotel", "guard", "guard"])), None), s(&["guard", "hotel"]), "sorted, no duplicates");
        if !cfg!(windows) {
            assert_eq!(resolve_features(Some(&s(&["hidepia"])), None), Vec::<String>::new(), "Windows-only option dropped elsewhere");
        }
    }

    #[test]
    fn choices_become_settings() {
        let mut c = Config::default();
        let o = Options { dns: Some("cloudflare".into()), user: Some("1000".into()), ..Default::default() };
        apply_choices(&mut c, &o, &s(&["guard", "dns"]), true).unwrap();
        assert_eq!(c.features, Some(Features { dns: true, hotel: false }));
        assert_eq!(c.provider(), "cloudflare");
        assert_eq!(c.mode, BlockMode::Startup, "a fresh install with the guard starts protected");
        assert_eq!(c.allowed_uids, vec![1000]);
        // upgrade: the mode stays
        c.mode = BlockMode::Always;
        apply_choices(&mut c, &Options::default(), &s(&["guard", "dns"]), false).unwrap();
        assert_eq!(c.mode, BlockMode::Always);
        assert_eq!(c.allowed_uids, vec![1000], "no duplicate user");
        // no guard -> no block
        apply_choices(&mut c, &Options::default(), &s(&["autostart"]), false).unwrap();
        assert_eq!(c.mode, BlockMode::Off);
        assert_eq!(c.features, Some(Features { dns: false, hotel: false }));
        // NextDNS without a profile is refused; with one it's saved
        let mut c = Config::default();
        let o = Options { dns: Some("nextdns".into()), ..Default::default() };
        assert!(apply_choices(&mut c, &o, &s(&["guard", "dns"]), true).unwrap_err().contains("profile ID"));
        let o = Options { dns: Some("nextdns".into()), nextdns_id: Some("abc123".into()), ..Default::default() };
        apply_choices(&mut c, &o, &s(&["guard", "dns"]), true).unwrap();
        assert_eq!(c.profile_id, "abc123");
        // a first install with no provider given gets Quad9 (no account needed)
        let mut c = Config::default();
        apply_choices(&mut c, &Options::default(), &s(&["guard", "dns"]), true).unwrap();
        assert_eq!(c.provider(), "quad9");
        // ... but NextDNS chosen with encrypted DNS OFF needs no profile
        let mut c = Config::default();
        apply_choices(&mut c, &Options { dns: Some("nextdns".into()), ..Default::default() }, &s(&["guard"]), true).unwrap();
        // custom needs its URL and addresses
        let mut c = Config::default();
        let o = Options { dns: Some("custom".into()), ..Default::default() };
        assert!(apply_choices(&mut c, &o, &s(&["guard", "dns"]), true).is_err());
        let o = Options {
            dns: Some("custom".into()),
            doh_url: Some("https://doh.example.net/dns-query".into()),
            doh_ips: Some(s(&["192.0.2.1"])),
            ..Default::default()
        };
        apply_choices(&mut c, &o, &s(&["guard", "dns"]), true).unwrap();
        assert_eq!(c.provider(), "custom");
        // Windows account IDs
        let mut c = Config::default();
        apply_choices(&mut c, &Options { user: Some("S-1-5-21-1-2-3-1001".into()), ..Default::default() }, &s(&["guard"]), true).unwrap();
        assert_eq!(c.allowed_sids.len(), 1);
        assert!(apply_choices(&mut c, &Options { user: Some("bob".into()), ..Default::default() }, &s(&["guard"]), true).is_err());
    }
}
