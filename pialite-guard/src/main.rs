//! PIA Lite guard - the background part of PIA Lite (a Windows service
//! running as LocalSystem, or a systemd service on Linux):
//!   * encrypted DNS: a DNS proxy on 127.0.0.1:53 -> DNS over HTTPS (DoH)
//!     to the provider chosen at install (NextDNS, Cloudflare, Quad9, ...)
//!   * internet block (kill switch): off / at startup until the VPN
//!     connects / always (Windows Filtering Platform, Linux nftables)
//!   * hotel Wi-Fi login mode
//!   * setup / teardown / updates for every installer (MSI, .deb, .rpm, ...)
//!
//! Run without arguments for the command list.

mod config;
mod dns;
mod doh;
mod firewall;
mod guard;
mod http;
mod ipc;
mod netif;
mod pia;
mod policy;
mod proxy;
mod setup;
mod sys;
mod update;

use pialite_common::ipc as client;
use pialite_common::status::{BlockMode, DnsHealth, GuardStatus};
use std::process::ExitCode;

#[cfg(windows)]
pub const SERVICE_NAME: &str = sys::SERVICE;

const HELP: &str = "PIA Lite guard   ((admin) = needs an administrator / root)
Everyday:
  pialite-guard status [--json]          what the guard is doing
  pialite-guard mode off|startup|always  internet block mode (making it weaker: admin)
  pialite-guard unlock                   (admin) EMERGENCY: turn the block off (stops a stuck service first)
  pialite-guard hotel start|stop         hotel Wi-Fi login, VPN off for a few minutes (start: admin)
Install and features:
  pialite-guard setup [options]          (admin) install or change PIA Lite's system parts:
      --features LIST                    guard,dns,hotel,autostart,hidepia (or none) - default: as before
      --dns PROVIDER                     nextdns | cloudflare | quad9 | adguard | google | custom
      --nextdns-id ID                    your NextDNS profile ID (with --dns nextdns)
      --doh-url URL --doh-ips IP,IP      your own server (with --dns custom): https://... or tls://...
      --doh-ca FILE                      its certificate authority (PEM), for a home server
      --mode off|startup|always          block mode (default: startup on a first install)
      --user ID                          account allowed to use the tray with the guard
      -i, --interactive                  ask the questions in this window
  pialite-guard teardown [--keep-config] (admin) remove the guard, its rules and settings; PIA put back
  pialite-guard features [--json]        what is installed
  pialite-guard dns-providers            the encrypted DNS providers to choose from
  pialite-guard set-dns PROVIDER [NEXTDNS-ID | URL IPS [CA-FILE]]
                                         (admin) switch the encrypted DNS provider; custom URL:
                                         https://host[:port]/path or tls://host[:port] (e.g. a Pi-hole)
  pialite-guard adapter-dns [--reset]    Windows: DNS set by hand on network adapters (it can bypass
                                         PIA Lite); --reset (admin) sets them back to automatic
  pialite-guard check-update [--json]    is there a newer release on GitHub?
  pialite-guard verify-release DIR       check a release folder (SHA256SUMS signed with the built-in key, every file)
  pialite-guard apply-update             (admin) download, verify (signed) and install it
Checks:
  pialite-guard test-dns [--json] [--canary DOMAIN]
                                         (admin) check lookups go: system -> guard -> provider over DoH;
                                         --canary (NextDNS): a domain on your Denylist proves YOUR profile
  pialite-guard test-doh [PROFILE]       talk to the DNS provider directly, without the proxy
  pialite-guard pipe-selftest            (Windows) check the control pipe's protections (run NOT as admin)
  pialite-guard selftest-firewall        (admin) install, check and remove real block rules - test machines only
                                         (refuses where PIA Lite is set up; --force)
                                         (Linux: only inside a test network namespace)
  pialite-guard set-profile ID [NAME]    (admin) NextDNS profile (+ device name)
  pialite-guard set-users ID[,ID..]      (admin) accounts allowed to control the guard
                                         (Windows account IDs S-1-5-..., or Linux user ids)
  pialite-guard check-rules              (admin) exit 0 only if checked and no PIA Lite rules are present
  pialite-guard show-rules [--json]      (admin) every PIA Lite firewall rule as the system holds it, checked
                                         (exit 1 if anything differs from what should be there)
  pialite-guard version                  this program's version
Service:
  pialite-guard run                      (root) run in the foreground - how systemd starts it on Linux
  pialite-guard console                  (admin) run in this window instead of as a service";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    let result = match a.as_slice() {
        ["service"] => run_service(),
        ["run"] => run_daemon(),
        ["console"] => {
            std::env::set_var("PIALITE_CONSOLE", "1");
            let g = guard::Guard::start();
            ipc::serve(g.clone());
            println!("PIA Lite guard running in this window. Press Enter to stop.");
            let _ = std::io::stdin().read_line(&mut String::new());
            g.shutdown();
            Ok(())
        }
        ["status"] => status(false),
        ["status", "--json"] => status(true),
        ["mode", m] if BlockMode::parse(m).is_some() => send(&format!("mode {m}")),
        ["unlock"] => unlock(),
        ["unlock", "--pause"] => unlock_window(),
        ["hotel", v @ ("start" | "stop")] => send(&format!("hotel {v}")),
        ["setup", rest @ ..] => setup::parse_args(rest).and_then(setup::setup),
        ["teardown"] => setup::teardown(false),
        ["teardown", "--keep-config"] => setup::teardown(true),
        ["features"] => setup::features_report(false),
        ["features", "--json"] => setup::features_report(true),
        ["dns-providers"] => dns_providers(),
        ["adapter-dns"] => setup::adapter_dns(false, false),
        ["adapter-dns", "--json"] => setup::adapter_dns(true, false),
        ["adapter-dns", "--reset"] => setup::adapter_dns(false, true),
        ["set-dns", rest @ ..] if !rest.is_empty() && rest.len() <= 4 => set_dns(rest),
        ["verify-release", dir] => update::verify_release(std::path::Path::new(dir)),
        ["check-update"] => update::check(false),
        ["check-update", "--json"] => update::check(true),
        ["apply-update"] => update::apply(),
        #[cfg(windows)]
        ["install-msi", file, log] => update::install_msi(file, log),
        ["firewall-close"] => firewall_close(),
        ["selftest-firewall"] => selftest_firewall(false),
        ["selftest-firewall", "--force"] => selftest_firewall(true),
        ["set-profile", id] => set_profile(id, None),
        ["set-profile", id, name] => set_profile(id, Some(name)),
        ["set-users", ids] => set_users(ids),
        ["test-dns"] => test_dns(false, None),
        ["test-dns", "--json"] => test_dns(true, None),
        ["test-dns", "--canary", d] => test_dns(false, Some(d)),
        ["test-dns", "--json", "--canary", d] | ["test-dns", "--canary", d, "--json"] => test_dns(true, Some(d)),
        ["pipe-selftest"] => pipe_selftest(),
        ["test-doh"] => test_doh(None),
        ["test-doh", id] => test_doh(Some(id)),
        ["check-rules"] => check_rules(),
        ["show-rules"] => show_rules(false),
        ["show-rules", "--json"] => show_rules(true),
        ["version"] | ["--version"] => {
            println!("pialite-guard {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        [] | ["help"] | ["--help"] | ["-h"] => {
            println!("{HELP}");
            Ok(())
        }
        _ => {
            println!("{HELP}");
            Err(format!("unknown command: {}", a.join(" ")))
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ERROR: {e}");
            ExitCode::FAILURE
        }
    }
}

const ADMIN_HINT: &str = if cfg!(windows) {
    "(Open the window with right-click > Run as administrator, or use the tray menu - it asks Windows for you.)"
} else {
    "(Run it with sudo, or use the tray menu - it asks for your password.)"
};

fn send(cmd: &str) -> Result<(), String> {
    match client::request(cmd) {
        Ok(m) => {
            println!("{m}");
            Ok(())
        }
        Err(e) if e == guard::NEEDS_ADMIN => Err(format!("{e}\n{ADMIN_HINT}")),
        Err(e) => Err(e),
    }
}

fn status(json: bool) -> Result<(), String> {
    match client::request("status") {
        Ok(j) => {
            let s: GuardStatus = serde_json::from_str(&j).map_err(|e| format!("unreadable status: {e}"))?;
            if json {
                println!("{j}");
            } else {
                println!("{}", pretty_status(&s));
            }
            Ok(())
        }
        Err(e) => {
            let present = firewall::installed();
            if json {
                let v = match &present {
                    Ok(b) => serde_json::json!({ "error": e, "rules_present": b }),
                    Err(why) => serde_json::json!({ "error": e, "rules_present": null, "rules_error": why }),
                };
                println!("{v}");
            } else {
                println!("{e}.");
                println!(
                    "Block rules in the firewall: {}",
                    match present {
                        Ok(true) => "PRESENT (internet blocked) - run `unlock` as admin if stuck".to_string(),
                        Ok(false) => "none".to_string(),
                        Err(why) => format!("could not check ({why})"),
                    }
                );
            }
            Err(e)
        }
    }
}

fn pretty_status(s: &GuardStatus) -> String {
    let mut out = vec![
        format!("PIA state      : {}", s.pia_state.as_deref().unwrap_or("not known yet / PIA service not reachable")),
        format!("Block mode     : {}  ({})", s.mode.as_str(), s.reason),
        format!(
            "Block rules    : {}{}",
            if s.armed { "in place" } else { "not in place" },
            match (s.mode, s.boot_rules) {
                (BlockMode::Off, _) => String::new(),
                (_, true) => ", boot-time rules in place".into(),
                (_, false) => format!(", boot-time rules NOT in place ({})", s.boot_rules_error),
            }
        ),
        format!("Blocking now   : {}", if s.blocking { "YES" } else { "no" }),
        format!(
            "PIA kill switch: {}{}",
            s.pia_killswitch,
            if s.mode == BlockMode::Startup && s.pia_killswitch != "on" {
                "  <- not 'Always': after the VPN drops, nothing blocks traffic (use mode 'always')"
            } else {
                ""
            }
        ),
        format!(
            "DNS proxy      : {}",
            if !s.dns.listening {
                format!("NOT listening on 127.0.0.1:53 ({})", s.dns.bind_error)
            } else if !s.profile_set {
                "listening, but no NextDNS profile set".into()
            } else {
                match s.dns.health {
                    DnsHealth::Untested => "listening, no lookups yet".into(),
                    DnsHealth::Ok => format!(
                        "OK - {} over {} ({} ms last lookup)",
                        provider_name(&s.dns_provider),
                        if s.dns_tls { "TLS" } else { "HTTPS" },
                        s.dns.last_ms
                    ),
                    DnsHealth::Degraded => "working, some recent lookups failed".into(),
                    DnsHealth::Down => format!("lookups failing: {}", s.dns.last_error),
                }
            }
        ),
        match s.dns_only_guard {
            Some(true) if cfg!(windows) => "Other DNS      : blocked - every lookup goes through the guard".to_string(),
            Some(true) => "Other DNS      : redirected to the guard".to_string(),
            Some(false) => format!(
                "Other DNS      : NOT {} - {}",
                if cfg!(windows) { "blocked" } else { "redirected" },
                if s.dns_only_guard_note.is_empty() { "not known yet" } else { &s.dns_only_guard_note }
            ),
            None => String::new(),
        },
        format!(
            "Lookups        : {} answered, {} failed, {} refused (overload), {} malformed",
            s.dns.answered, s.dns.failed, s.dns.overloaded, s.dns.malformed
        ),
        format!(
            "Network        : {}",
            match s.network_ready {
                Some(true) => "up",
                Some(false) => "none usable yet (PIA is asked to connect once there is one)",
                None => "not known",
            }
        ),
        format!(
            "VPN adapter    : {}",
            match s.tunnel_watch.as_str() {
                "" => "- (VPN not connected)".to_string(),
                "checking" => "looking for PIA's adapter...".to_string(),
                "up" => format!(
                    "{} - PIA adapter observed up (the system reports it up; not a test of the tunnel itself){}",
                    s.vpn_adapter,
                    match s.route_via_vpn {
                        Some(true) => "; DNS-over-HTTPS traffic is routed through it",
                        Some(false) => "; NOTE: DNS-over-HTTPS traffic is NOT routed through it",
                        None => "",
                    }
                ),
                "down" => format!("{} - DOWN although PIA says Connected", s.vpn_adapter),
                "not-found" => "none of PIA's adapters is up although PIA says Connected".to_string(),
                "query-failed" => format!("{} (the last look at the adapters failed)", s.vpn_adapter),
                other => other.to_string(),
            }
        ),
    ];
    if s.hotel {
        out.push(format!("Hotel login    : ON, {} s left - traffic is outside the VPN", s.hotel_left));
    }
    if s.restore_pending {
        out.push("WARNING        : PIA's kill switch not restored after hotel login yet (retrying; the guard blocks whenever the VPN is down meanwhile)".into());
    }
    if s.approved_accounts == 0 && cfg!(windows) {
        out.push(
            "NOTE           : no Windows account approved for the tray - only admins can talk to the guard (re-run the installer)".into(),
        );
    }
    if !s.notice.is_empty() {
        out.push(format!("NOTICE         : {}", s.notice));
    }
    for (label, e) in [("Settings", &s.config_error), ("Firewall", &s.fw_error)] {
        if !e.is_empty() {
            out.push(format!("PROBLEM ({label}): {e}"));
        }
    }
    out.retain(|l| !l.is_empty());
    out.join("\n")
}

/// Emergency: through the service if it answers; if it's stopped, directly;
/// if it runs but doesn't answer (busy, stuck), stop it, unlock directly and
/// start it again (review V3-06). Needs an administrator.
fn unlock() -> Result<(), String> {
    match client::request("unlock") {
        Ok(m) => {
            println!("Unlocked: {m}");
            return Ok(());
        }
        Err(e) if e == guard::NEEDS_ADMIN => {
            return Err(if cfg!(windows) {
                "unlocking needs an administrator: use Start menu > PIA Lite > Unlock Internet (it asks Windows for you)".into()
            } else {
                "unlocking needs root: sudo pialite-guard unlock".into()
            })
        }
        Err(e) if e == "guard service not running" => {}
        Err(e) => {
            println!("The guard service didn't unlock ({e}) - stopping it to unlock directly...");
            sys::stop_service()?;
            offline_unlock()?;
            match sys::start_service() {
                Ok(()) => println!("Guard service started again (block off)."),
                Err(e) => println!("Note: the guard service did not start again ({e}) - DNS may not work until it does; restart the PC."),
            }
            return Ok(());
        }
    }
    offline_unlock()
}

/// The Start-menu "Unlock Internet" shortcut: asks for administrator
/// rights itself, shows the result and waits for Enter.
fn unlock_window() -> Result<(), String> {
    #[cfg(windows)]
    if !sys::is_admin() {
        let me = std::env::current_exe().map_err(|e| e.to_string())?;
        let cmd = format!(
            "Start-Process -Verb RunAs -FilePath '{}' -ArgumentList 'unlock','--pause'",
            me.display().to_string().replace('\'', "''")
        );
        return sys::run("powershell.exe", &["-NoProfile", "-WindowStyle", "Hidden", "-Command", &cmd]).map(|_| ());
    }
    println!("PIA Lite - Unlock Internet\n");
    let r = unlock();
    if let Err(e) = &r {
        println!("ERROR: {e}");
    }
    println!("\nPress Enter to close.");
    let _ = std::io::stdin().read_line(&mut String::new());
    r
}

fn offline_unlock() -> Result<(), String> {
    firewall::uninstall().map_err(|e| format!("{e}\n{ADMIN_HINT}"))?;
    let _ = firewall::reset_open();
    let mut cfg = config::load(|| true).config().clone();
    cfg.mode = BlockMode::Off;
    config::save(&cfg)?;
    config::log("UNLOCK used while the service was stopped - block rules removed, mode off");
    println!("Unlocked: block rules removed and the block is now OFF.");
    Ok(())
}

/// Settings that decide what the guard trusts: through the running service
/// (which then is the only writer), or written directly if it's stopped.
fn admin_setting(cmd: &str, offline: impl FnOnce(&mut config::Config)) -> Result<(), String> {
    match client::request(cmd) {
        Ok(m) => {
            println!("{m}");
            Ok(())
        }
        Err(e) if e == "guard service not running" => {
            if !sys::is_admin() {
                return Err(format!("{}\n{ADMIN_HINT}", guard::NEEDS_ADMIN));
            }
            let mut cfg = config::load(|| true).config().clone();
            offline(&mut cfg);
            config::save(&cfg)?;
            println!("saved (the guard service will use it when it starts)");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn set_profile(id: &str, name: Option<&str>) -> Result<(), String> {
    if !config::valid_profile(id) {
        return Err("that doesn't look like a NextDNS profile ID (letters/numbers, e.g. abc123)".into());
    }
    let name: Option<String> = name.map(|n| n.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect());
    let cmd = match &name {
        Some(n) => format!("set_profile {id} {n}"),
        None => format!("set_profile {id}"),
    };
    admin_setting(&cmd, |c| {
        c.profile_id = id.to_string();
        if let Some(n) = name {
            c.device_name = n;
        }
    })
}

fn set_users(ids: &str) -> Result<(), String> {
    let list: Vec<String> = ids.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    if !list.is_empty() && list.iter().all(|s| s.parse::<u32>().is_ok()) {
        let uids: Vec<u32> = list.iter().filter_map(|s| s.parse().ok()).collect();
        return admin_setting(&format!("set_users {}", list.join(",")), |c| c.allowed_uids = uids.clone());
    }
    if list.is_empty() || list.iter().any(|s| !config::valid_sid(s)) {
        return Err("expected Windows account IDs like S-1-5-21-... or Linux user ids like 1000".into());
    }
    admin_setting(&format!("set_users {}", list.join(",")), |c| c.allowed_sids = list.clone())
}

fn provider_name(id: &str) -> &str {
    match id {
        "" => "encrypted DNS",
        "custom" => "your DNS server",
        _ => config::preset(id).map(|p| p.name).unwrap_or(id),
    }
}

fn dns_providers() -> Result<(), String> {
    for p in config::DNS_PRESETS {
        println!("{:<11} {}", p.id, p.name);
    }
    println!("{:<11} your own DNS-over-HTTPS server: set-dns custom https://host/path IP[,IP]", "custom");
    Ok(())
}

/// set-dns PROVIDER | set-dns nextdns ID | set-dns custom URL IPS
fn set_dns(rest: &[&str]) -> Result<(), String> {
    match rest {
        ["custom", url, ips] => {
            let list: Vec<String> = ips.split(',').map(|s| s.trim().to_string()).collect();
            let mut probe = config::Config::default();
            probe.set_provider("custom", Some((url, &list)))?; // checked before it is sent
            send(&format!("set_dns custom {url} {}", list.join(",")))
        }
        ["custom", url, ips, ca_file] => {
            let list: Vec<String> = ips.split(',').map(|s| s.trim().to_string()).collect();
            let mut probe = config::Config::default();
            probe.set_provider("custom", Some((url, &list)))?;
            setup::install_ca_file(std::path::Path::new(ca_file))?;
            send(&format!("set_dns custom {url} {} ca", list.join(",")))
        }
        ["nextdns", id] => {
            set_profile(id, None)?;
            send("set_dns nextdns")
        }
        [p] if config::preset(p).is_some() => send(&format!("set_dns {p}")),
        _ => Err(format!(
            "usage: set-dns {} | set-dns nextdns ID | set-dns custom URL IP[,IP] [CA-FILE]\n  URL: https://host[:port]/path (DNS over HTTPS) or tls://host[:port] (DNS over TLS)\n  CA-FILE: the server's own certificate authority (PEM), e.g. a Pi-hole's",
            config::preset_ids()
        )),
    }
}

/// systemd ExecStopPost (Linux): the guard's temporary allow-all and DNS
/// redirect go with it - also after a crash. Windows drops its own.
fn firewall_close() -> Result<(), String> {
    firewall::reset_open()?;
    firewall::dns_capture(false)
}

/// Exit 0 ONLY when Windows' firewall was actually looked at and holds no
/// PIA Lite rules. "Couldn't look" is a failure, never "none" (review V3-01).
fn check_rules() -> Result<(), String> {
    match firewall::installed() {
        Ok(false) => {
            println!("no PIA Lite block rules in the firewall (checked)");
            Ok(())
        }
        Ok(true) => Err("block rules are still present in the firewall".into()),
        Err(e) => Err(format!("could NOT check the firewall rules ({e}) - not assuming there are none")),
    }
}

/// What should be in Windows, and on what basis (review F51-03): the
/// guard's own statement of what it WANTS - never inferred from what it saw.
#[derive(Debug, PartialEq)]
struct Want {
    rules: bool,
    boot: bool,
    basis: String,
    /// Why boot-time rules aren't there although wanted (Windows refused them).
    boot_note: String,
}

/// From a running guard; None = a guard too old to say what it wants.
fn want_from_status(st: &GuardStatus) -> Option<Want> {
    let (Some(rules), Some(boot), Some(eff)) = (st.rules_wanted, st.boot_rules_wanted, st.effective_mode) else { return None };
    let mut basis = format!("running guard: block mode {}", st.mode.as_str());
    if eff != st.mode {
        basis += &format!(", acting as {} until PIA's kill switch is back", eff.as_str());
    }
    if !boot && rules {
        basis += ", boot-time rules turned off";
    }
    Some(Want { rules, boot, basis, boot_note: st.boot_rules_error.clone() })
}

/// The guard isn't running: what it would want from its saved settings - the
/// same rule as the guard (an unfinished hotel login acts as Always).
fn want_from_saved(cfg: &config::Config, strict: bool, why: &str) -> Want {
    let eff = if strict { BlockMode::Always } else { cfg.mode };
    let rules = eff != BlockMode::Off;
    let boot = rules && cfg.boot_time_rules;
    let mut basis = format!("{why} - saved block mode {}", cfg.mode.as_str());
    if eff != cfg.mode {
        basis += ", acting as always (unfinished hotel login)";
    }
    if rules && !boot {
        basis += ", boot-time rules turned off";
    }
    Want { rules, boot, basis, boot_note: String::new() }
}

/// Wanted vs present, both ways, for both kinds of rule: wanted + present ->
/// checked exactly; wanted + missing, or present + not wanted -> a difference.
fn rule_checks(
    w: &Want,
    have_persistent: bool,
    have_boot: bool,
    verify_persistent: impl FnOnce() -> Result<(), String>,
    verify_boot: impl FnOnce() -> Result<(), String>,
) -> Vec<(&'static str, Result<(), String>)> {
    let mut out = vec![];
    match (w.rules, have_persistent) {
        (true, true) => out.push(("persistent rules", verify_persistent())),
        (true, false) => out.push(("persistent rules", Err(format!("expected, but not in the firewall ({})", w.basis)))),
        (false, true) => out.push(("persistent rules", Err(format!("in the firewall although none are wanted ({})", w.basis)))),
        (false, false) => {}
    }
    match (w.boot, have_boot) {
        (true, true) => out.push(("boot-time rules", verify_boot())),
        (true, false) => {
            let note = if w.boot_note.is_empty() { String::new() } else { format!(" - the system refused them: {}", w.boot_note) };
            out.push(("boot-time rules", Err(format!("expected, but not in the firewall ({}){note}", w.basis))))
        }
        (false, true) => out.push(("boot-time rules", Err(format!("in the firewall although not wanted ({})", w.basis)))),
        (false, false) => {}
    }
    out
}

/// Every PIA Lite filter as Windows holds it, then the same check the guard
/// runs every 30 s against what the plan would be right now (review V3-05:
/// evidence with field keys, match types and values). Exit code 1 when
/// anything differs: rules wanted but missing, present but not wanted, or
/// present but changed - for the block rules and the boot-time rules alike
/// (review V4-05, F51-03). `--json` for scripts.
fn show_rules(json: bool) -> Result<(), String> {
    let lines = firewall::describe()?;
    let has = |p: &str| lines.iter().any(|l| l.starts_with(p));
    // what SHOULD be there: the running guard says what it wants, else the saved settings
    let status = client::request_within("status", std::time::Duration::from_secs(10))
        .ok()
        .and_then(|j| serde_json::from_str::<GuardStatus>(&j).ok());
    let saved = || {
        // no settings at all: only Windows' actual rules decide whether a
        // protective setting is assumed (an error looking = assume rules, fail
        // safe) - never invent wanted rules on a clean PC (review V60-04)
        let c = config::load(|| firewall::installed().unwrap_or(true)).config().clone();
        let strict = config::strict_for(&c);
        (c, strict)
    };
    let want = match &status {
        Some(st) => want_from_status(st).unwrap_or_else(|| {
            let (c, strict) = saved();
            want_from_saved(&c, strict, &format!("running guard {} doesn't say what it wants", st.version))
        }),
        None => {
            let (c, strict) = saved();
            want_from_saved(&c, strict, "guard not running")
        }
    };
    let checks = rule_checks(
        &want,
        has("persistent"),
        has("boot-time"),
        || firewall::verify(&firewall::specs(&firewall::plan(&pia::engine_exes(), pia::allow_lan_or_safe()), firewall::Kind::Persistent)),
        || firewall::verify(&firewall::specs(&firewall::boot_plan(), firewall::Kind::BootTime)),
    );
    let diffs = checks.iter().filter(|(_, r)| r.is_err()).count();
    if json {
        let list: Vec<serde_json::Value> = checks
            .iter()
            .map(|(w, r)| serde_json::json!({ "what": w, "ok": r.is_ok(), "detail": r.as_ref().err().cloned().unwrap_or_default() }))
            .collect();
        println!(
            "{}",
            serde_json::json!({ "rules": lines, "expected": want.rules, "expected_boot": want.boot, "basis": want.basis, "checks": list, "ok": diffs == 0 })
        );
    } else {
        if lines.is_empty() {
            println!("no PIA Lite rules in the firewall");
        }
        for l in &lines {
            println!("{l}");
        }
        if checks.is_empty() {
            println!("CHECK-OK: no PIA Lite rules, and none are wanted ({})", want.basis);
        }
        for (what, r) in &checks {
            match r {
                Ok(()) => println!("CHECK-OK: {what} match the plan exactly (field, match type and value of every condition)"),
                Err(e) => println!("CHECK-DIFF: {what}: {e}"),
            }
        }
    }
    if diffs > 0 {
        Err(format!("{diffs} check(s) differ"))
    } else {
        Ok(())
    }
}

fn query_proxy(name: &str, qtype: u16) -> Result<Vec<u8>, String> {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    s.set_read_timeout(Some(std::time::Duration::from_secs(8))).map_err(|e| e.to_string())?;
    let id = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(7) & 0xFFFF) as u16;
    let q = dns::build_query(id, name, qtype)?;
    s.send_to(&q, guard::DNS_ADDR).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 4096];
    let (n, from) = s.recv_from(&mut buf).map_err(|_| "no answer from 127.0.0.1:53 within 8 s".to_string())?;
    let a = buf[..n].to_vec();
    if from.to_string() != guard::DNS_ADDR || dns::id(&a) != Some(id) {
        return Err("answer did not come from the guard's DNS proxy".into());
    }
    dns::check_response(&a, &q)?;
    Ok(a)
}

/// Look a name up through the proxy, expecting real records. Tries 3 times,
/// because right after a VPN reconnect the first try can be slow.
fn lookup_ok(name: &str) -> Result<Vec<u8>, String> {
    let mut last = String::new();
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        match query_proxy(name, 1) {
            Ok(a) => match dns::summary(&a) {
                Some((0, n)) if n > 0 => return Ok(a),
                Some((2, _)) => last = "SERVFAIL - the guard couldn't reach the DNS provider (VPN not connected?)".into(),
                other => last = format!("unexpected answer for {name}: {other:?}"),
            },
            Err(e) => last = e,
        }
    }
    Err(last)
}

/// NextDNS's own test page: (status, protocol, profile) as NextDNS saw our lookup.
fn nextdns_test_page() -> Result<(String, String, String), String> {
    // test.nextdns.io redirects to a one-off name (https://<random>.test.nextdns.io/):
    // looking THAT up through the guard is what NextDNS then reports on.
    let (mut host, mut path) = ("test.nextdns.io".to_string(), "/".to_string());
    let mut body = String::new();
    for _ in 0..3 {
        let a = lookup_ok(&host)?;
        let ip = *dns::a_records(&a).first().ok_or(format!("no address for {host}"))?;
        let r = doh::https_get(std::net::SocketAddr::new(ip.into(), 443), &host, &path)?;
        if r.status == 200 {
            body = String::from_utf8_lossy(&r.body).into_owned();
            break;
        }
        (host, path) = redirect_target(&r.location)?;
    }
    let v: serde_json::Value =
        serde_json::from_str(&body).map_err(|_| format!("test page sent something unexpected: {:.60}", body.trim()))?;
    let field = |k: &str| v[k].as_str().unwrap_or("").to_string();
    Ok((field("status"), field("protocol"), field("profile")))
}

/// Follow only https redirects that stay on nextdns.io.
fn redirect_target(location: &str) -> Result<(String, String), String> {
    let rest = location.strip_prefix("https://").ok_or(format!("unexpected redirect to {location:.60}"))?;
    let (hostport, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let host = hostport.split(':').next().unwrap_or("").to_ascii_lowercase();
    if !(host == "nextdns.io" || host.ends_with(".nextdns.io")) || host.len() > 253 {
        return Err(format!("unexpected redirect to {host:.60}"));
    }
    Ok((host, path.to_string()))
}

/// What NextDNS's test page says about the profile (review N-10).
#[derive(Debug, PartialEq)]
enum ProfileCheck {
    /// The page names our profile, or our Denylist canary was blocked.
    Match(String),
    /// The page names another profile / no profile, or the canary got through.
    Mismatch(String),
    /// Can't tell (NextDNS shows an anonymous fingerprint) - NOT verified.
    Unknown(String),
}

fn profile_from_page(seen: &str, mine: &str) -> ProfileCheck {
    if seen.is_empty() {
        ProfileCheck::Mismatch("NextDNS sees NO profile for this lookup".into())
    } else if seen.starts_with("fp") {
        // NextDNS shows a hashed fingerprint, not the ID itself: can't be compared
        ProfileCheck::Unknown("NextDNS only shows an anonymous fingerprint of the profile".into())
    } else if !mine.is_empty() && seen.eq_ignore_ascii_case(mine) {
        ProfileCheck::Match("NextDNS names your profile".into())
    } else {
        ProfileCheck::Mismatch(format!("NextDNS reports profile '{seen}', the guard is set to '{mine}'"))
    }
}

/// Opt-in proof of YOUR profile: a domain you put on that profile's Denylist
/// must come back blocked through the guard, while NextDNS WITHOUT a profile
/// answers it normally (the control - so a domain that doesn't exist, or is
/// blocked for everyone, can't pass as proof).
fn canary_check(domain: &str) -> ProfileCheck {
    use doh::Resolve;
    let a = (0..3).find_map(|i| {
        if i > 0 {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        query_proxy(domain, 1).ok()
    });
    let Some(a) = a else { return ProfileCheck::Unknown(format!("could not look up the canary {domain}")) };
    // control: the same name from NextDNS with no profile at all
    let mut anon = config::load(|| false).config().clone();
    anon.profile_id.clear();
    let control = dns::build_query(0x4243, domain, 1).and_then(|q| doh::Doh::from_config(&anon)?.resolve(&q));
    let real = |r: &[u8]| matches!(dns::summary(r), Some((0, _))) && dns::a_records(r).iter().any(|ip| !ip.is_unspecified());
    match &control {
        Ok(c) if real(c) => {}
        Ok(_) => {
            return ProfileCheck::Unknown(format!(
                "{domain} doesn't resolve even without a profile - pick a domain that exists, e.g. example.net"
            ))
        }
        Err(e) => return ProfileCheck::Unknown(format!("could not ask NextDNS without a profile for the comparison: {e}")),
    }
    let ips = dns::a_records(&a);
    match dns::summary(&a) {
        Some((3, _)) => {
            ProfileCheck::Match(format!("{domain} was blocked through the guard (no such name) but resolves without your profile"))
        }
        Some((0, _)) if !ips.is_empty() && ips.iter().all(|ip| ip.is_unspecified()) => {
            ProfileCheck::Match(format!("{domain} was blocked through the guard (0.0.0.0) but resolves without your profile"))
        }
        Some((0, _)) if !ips.is_empty() => {
            ProfileCheck::Mismatch(format!("{domain} was NOT blocked - lookups are not using the profile with that Denylist entry"))
        }
        other => ProfileCheck::Unknown(format!("unexpected answer for the canary: {other:?}")),
    }
}

/// Does Windows' own resolver (what browsers and apps use) send lookups to
/// the guard? Looks up a random one-off name with getaddrinfo and asks the
/// guard whether it saw it (review N-11). Some(true/false), None = can't tell.
fn os_resolver_check() -> (Option<bool>, String) {
    use std::net::ToSocketAddrs;
    let mut note = String::new();
    for attempt in 0..3 {
        if attempt > 0 {
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(0);
        let name = format!("pialite-{nanos:x}-{:x}.test.nextdns.io", std::process::id());
        let _ = (name.as_str(), 443).to_socket_addrs(); // the answer doesn't matter, only who was asked
        for _ in 0..4 {
            match client::request(&format!("seen {name}")) {
                Ok(v) if v == "yes" => return (Some(true), "the system's resolver asked the guard".into()),
                Ok(_) => std::thread::sleep(std::time::Duration::from_millis(250)),
                Err(e) if e == guard::NEEDS_ADMIN => return (None, "can't check without administrator rights".into()),
                Err(e) => return (None, format!("can't check: {e}")),
            }
        }
        note = if cfg!(windows) {
            "the system's resolver did NOT send a test lookup to the guard - it uses another DNS server. \
             PIA applies its DNS setting when it connects: if PIA Lite was installed or changed while \
             connected, disconnect and reconnect PIA, then try again"
        } else {
            "the system's resolver did NOT send a test lookup to the guard - it uses another DNS server"
        }
        .into();
    }
    (Some(false), note)
}

/// Prove the path system resolver -> 127.0.0.1 -> guard -> provider (DoH),
/// and say plainly what is and isn't proven. NextDNS has a test page that
/// shows how a lookup arrived; with the other providers the proof is that
/// lookups are answered by the guard, which only ever forwards over HTTPS.
///   proxy:      real lookups answered through the guard - required
///   page:       NextDNS's test page sees our lookup as DoH through NextDNS - required
///   os:         Windows' own resolver sends lookups to the guard - required
///               ("can't tell" when not run as admin)
///   profile:    match / mismatch (fails) / unknown (reported as NOT verified)
fn test_dns(json: bool, canary: Option<&str>) -> Result<(), String> {
    if let Some(d) = canary {
        if d.is_empty() || d.len() > 253 || !d.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.') {
            return Err("the canary must be a plain domain name like canary-example.com".into());
        }
    }
    let mut report = serde_json::Map::new();
    let mut put = |k: &str, v: serde_json::Value| {
        report.insert(k.into(), v);
    };
    let proxy = lookup_ok("example.com");
    put("proxy_ok", proxy.is_ok().into());
    let provider = config::load(|| false).config().provider().to_string();
    let nextdns = provider == "nextdns";
    put("provider", provider.clone().into());
    let mut errors: Vec<String> = vec![];
    let mut profile = ProfileCheck::Unknown("not checked".into());
    let mut encrypted = false;
    match &proxy {
        Err(e) => {
            put("proxy_error", e.clone().into());
            errors.push(e.clone());
        }
        Ok(_) if !nextdns => {
            // the proxy has no other way out than DoH to the provider
            put("page_checked", false.into());
            encrypted = true;
            profile = ProfileCheck::Match(format!("{} has no profile to check", provider_name(&provider)));
        }
        Ok(_) => match nextdns_test_page() {
            Ok((status, protocol, seen)) => {
                let mine = config::load(|| false).config().profile_id.clone();
                put("page_checked", true.into());
                put("nextdns_status", status.clone().into());
                put("protocol", protocol.clone().into());
                put("profile_seen", seen.clone().into());
                put("profile_saved", mine.clone().into());
                if status != "ok" {
                    errors.push(format!("NextDNS says the lookup did NOT go through NextDNS (status '{status}')"));
                } else if protocol != "DOH" {
                    errors.push(format!("NextDNS saw protocol '{protocol}', expected DOH"));
                } else {
                    encrypted = true;
                }
                profile = profile_from_page(&seen, &mine);
            }
            Err(e) => {
                put("page_checked", false.into());
                put("page_error", e.clone().into());
                errors.push(format!("NextDNS's test page could not be checked: {e}"));
            }
        },
    }
    if let (Some(d), true) = (canary, proxy.is_ok() && nextdns) {
        // a canary decides the profile question either way
        profile = match canary_check(d) {
            ProfileCheck::Unknown(why) => ProfileCheck::Unknown(why),
            decided => decided,
        };
        put("canary", d.into());
    }
    let (os, os_note) = if proxy.is_ok() { os_resolver_check() } else { (None, "not checked".into()) };
    put(
        "os_resolver",
        match os {
            Some(true) => "proxy",
            Some(false) => "elsewhere",
            None => "unknown",
        }
        .into(),
    );
    put("os_resolver_note", os_note.clone().into());
    if os == Some(false) {
        errors.push(os_note.clone());
    }
    let (pcheck, pnote) = match &profile {
        ProfileCheck::Match(n) => ("match", n.clone()),
        ProfileCheck::Mismatch(n) => ("mismatch", n.clone()),
        ProfileCheck::Unknown(n) => ("unknown", n.clone()),
    };
    if let ProfileCheck::Mismatch(n) = &profile {
        errors.push(n.clone());
    }
    put("encrypted_ok", encrypted.into());
    // three separate gates (review V3-09): the installer requires the first two
    put("transport_ok", (proxy.is_ok() && encrypted).into());
    put("resolver_verified", (os == Some(true)).into());
    put("profile_verified", (pcheck == "match").into());
    put("profile_check", pcheck.into());
    put("profile_note", pnote.clone().into());
    let ok = errors.is_empty();
    let fully = ok && pcheck == "match" && os == Some(true);
    put("ok", ok.into());
    put("fully_verified", fully.into());
    if !ok {
        put("error", errors.join("; ").into());
    }
    if json {
        // machine-readable: JSON only on stdout, the exit code says pass/fail
        println!("{}", serde_json::Value::Object(report));
    } else {
        let yn = |b: bool| if b { "YES" } else { "NO" };
        println!("Lookups answered by the guard        : {}", yn(proxy.is_ok()));
        println!("Encrypted via {:<23}: {}", provider_name(&provider), yn(encrypted));
        println!(
            "The system's resolver uses the guard : {}",
            match os {
                Some(b) => yn(b).to_string(),
                None => format!("NOT CHECKED ({os_note})"),
            }
        );
        if nextdns {
            println!(
                "Your NextDNS profile                 : {}",
                match pcheck {
                    "match" => format!("CONFIRMED - {pnote}"),
                    "mismatch" => format!("WRONG - {pnote}"),
                    _ => format!("NOT CONFIRMED - {pnote}"),
                }
            );
        }
        if nextdns && pcheck == "unknown" && canary.is_none() {
            println!("  To confirm it: add a test domain to your profile's Denylist on my.nextdns.io,");
            println!("  then run: pialite-guard test-dns --canary <that domain>");
        }
    }
    if ok {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Talk to the provider directly with the saved settings (no proxy).
/// PROFILE: a NextDNS profile ID to try instead of the saved one.
fn test_doh(profile: Option<&str>) -> Result<(), String> {
    use doh::Resolve;
    let mut cfg = config::load(|| false).config().clone();
    if let Some(id) = profile {
        if !config::valid_profile(id) {
            return Err("that doesn't look like a NextDNS profile ID".into());
        }
        cfg.set_provider("nextdns", None)?;
        cfg.profile_id = id.to_string();
    }
    if cfg.provider() == "nextdns" && cfg.profile_id.is_empty() {
        return Err("no NextDNS profile saved yet".into());
    }
    let name = provider_name(cfg.provider()).to_string();
    let how = if cfg.dot() { "TLS" } else { "HTTPS" };
    let d = doh::Doh::from_config(&cfg)?;
    let a = d.resolve(&dns::build_query(0x4242, "example.com", 1)?)?;
    match dns::summary(&a) {
        Some((0, n)) if n > 0 => {
            println!("OK: {name} answered over {how} ({n} records)");
            Ok(())
        }
        other => Err(format!("{name} answered oddly: {other:?}")),
    }
}

/// Checks of the control pipe's protections, run as a normal (not elevated)
/// user (review N-04, N-05). Prints PASS/FAIL/WARN lines; exit 1 on a FAIL.
#[cfg(windows)]
fn pipe_selftest() -> Result<(), String> {
    use std::io::Write;
    use std::time::{Duration, Instant};
    let mut fails = 0;
    let mut line = |verdict: &str, msg: String| {
        if verdict == "FAIL" {
            fails += 1;
        }
        println!("{verdict}: {msg}");
    };
    println!("PIA Lite control pipe self-test (guard {})", env!("CARGO_PKG_VERSION"));
    let who = match client::request("whoami") {
        Ok(w) => w,
        Err(e) => {
            println!("FAIL: can't reach the guard: {e}");
            return Err(e);
        }
    };
    if who == "user" {
        line("PASS", "this (not elevated) program is treated as a normal user".into());
    } else {
        line("WARN", "this window is elevated - run pipe-selftest from a normal window for a meaningful test".into());
    }

    // 1. a normal user must not be able to create another instance of the pipe
    {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ACCESS_DENIED, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::PIPE_ACCESS_DUPLEX;
        use windows_sys::Win32::System::Pipes::{CreateNamedPipeW, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE};
        let name: Vec<u16> = client::PIPE_NAME.encode_utf16().chain(Some(0)).collect();
        let h = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_REJECT_REMOTE_CLIENTS,
                255,
                4096,
                4096,
                0,
                std::ptr::null(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            let e = unsafe { GetLastError() };
            if e == ERROR_ACCESS_DENIED {
                line("PASS", "creating a second instance of the guard's pipe is refused (access denied)".into());
            } else {
                line("WARN", format!("creating a second pipe instance failed with error {e} (expected 5 = access denied)"));
            }
        } else {
            unsafe { CloseHandle(h) };
            line(if who == "user" { "FAIL" } else { "WARN" }, "a second instance of the guard's pipe COULD be created".into());
        }
    }

    // 2. a weakening command needs an administrator
    if who == "user" {
        let before: Option<String> =
            client::request("status").ok().and_then(|j| serde_json::from_str::<GuardStatus>(&j).ok()).map(|s| s.mode.as_str().to_string());
        match client::request("unlock") {
            Err(e) if e.contains("administrator") => line("PASS", "'unlock' from a normal user is refused".into()),
            Err(e) => line("WARN", format!("'unlock' refused for another reason: {e}")),
            Ok(_) => {
                line("FAIL", "'unlock' from a normal user was ACCEPTED".into());
                if let Some(m) = before {
                    let _ = client::request(&format!("mode {m}")); // stronger again: allowed
                    println!("      (block mode put back to '{m}')");
                }
            }
        }
    }

    // 3. four clients that never read their replies must not lock others out
    let mut stalled = vec![];
    for _ in 0..4 {
        match client::open_pipe() {
            Ok(mut f) => {
                let _ = f.write_all(client::format_request("status").as_bytes());
                stalled.push(f);
            }
            Err(e) => {
                line("WARN", format!("could not open a test connection: {e}"));
                break;
            }
        }
    }
    let t = Instant::now();
    let limit = Duration::from_secs(20);
    let got = loop {
        match client::request("ping") {
            Ok(_) => break true,
            Err(_) if t.elapsed() < limit => std::thread::sleep(Duration::from_millis(300)),
            Err(_) => break false,
        }
    };
    let n = stalled.len();
    drop(stalled);
    if got {
        line("PASS", format!("with {n} stuck clients, another client got an answer after {:.1} s (limit 20 s)", t.elapsed().as_secs_f32()));
    } else {
        line("FAIL", format!("with {n} stuck clients, no answer within 20 s"));
    }
    if fails > 0 {
        Err(format!("{fails} check(s) failed"))
    } else {
        Ok(())
    }
}
#[cfg(not(windows))]
fn pipe_selftest() -> Result<(), String> {
    Err("the pipe self-test only runs on Windows".into())
}

// ------------------------------------------------------------ Windows service

#[cfg(windows)]
mod service {
    use super::*;
    use std::ffi::OsString;
    use std::sync::mpsc;
    use std::time::Duration;
    use windows_service::service::{
        PowerEventParam, ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::{define_windows_service, service_dispatcher};

    define_windows_service!(ffi_service_main, service_main);

    pub fn run() -> Result<(), String> {
        service_dispatcher::start(SERVICE_NAME, ffi_service_main).map_err(|e| format!("not started by Windows service manager: {e}"))
    }

    fn status(state: ServiceState) -> ServiceStatus {
        ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN | ServiceControlAccept::POWER_EVENT
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::from_secs(5),
            process_id: None,
        }
    }

    enum Msg {
        Stop,
        Rearm(&'static str),
    }

    fn service_main(_args: Vec<OsString>) {
        let (tx, rx) = mpsc::channel();
        let handler = move |c| match c {
            ServiceControl::Stop | ServiceControl::Shutdown => {
                let _ = tx.send(Msg::Stop);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::PowerEvent(p) => {
                let why = match p {
                    PowerEventParam::Suspend => Some("going to sleep/hibernate"),
                    PowerEventParam::ResumeAutomatic | PowerEventParam::ResumeSuspend => Some("woke up"),
                    _ => None,
                };
                if let Some(w) = why {
                    let _ = tx.send(Msg::Rearm(w));
                }
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        };
        let Ok(h) = service_control_handler::register(SERVICE_NAME, handler) else { return };
        let _ = h.set_service_status(status(ServiceState::Running));
        let g = guard::Guard::start();
        ipc::serve(g.clone());
        while let Ok(msg) = rx.recv() {
            match msg {
                Msg::Stop => break,
                Msg::Rearm(why) => g.rearm(why),
            }
        }
        let _ = h.set_service_status(status(ServiceState::StopPending));
        g.shutdown();
        let _ = h.set_service_status(status(ServiceState::Stopped));
    }
}

#[cfg(windows)]
fn run_service() -> Result<(), String> {
    service::run()
}
#[cfg(not(windows))]
fn run_service() -> Result<(), String> {
    Err("Windows services only exist on Windows - on Linux systemd runs `pialite-guard run`".into())
}

/// Linux: the guard in the foreground until SIGTERM/SIGINT (systemd's
/// pialite-guard.service). Waking from sleep is noticed by the clocks:
/// CLOCK_BOOTTIME keeps counting while suspended, CLOCK_MONOTONIC doesn't.
#[cfg(not(windows))]
fn run_daemon() -> Result<(), String> {
    if !sys::is_admin() {
        return Err("the guard runs as root (systemd starts it: systemctl start pialite-guard)".into());
    }
    // signals are waited for below - blocked BEFORE any thread starts, so
    // every thread inherits the mask and none is killed by them
    let mut set: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTERM);
        libc::sigaddset(&mut set, libc::SIGINT);
        libc::sigaddset(&mut set, libc::SIGHUP);
        libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
    }
    let g = guard::Guard::start();
    ipc::serve(g.clone());
    let g2 = g.clone();
    std::thread::spawn(move || {
        let gap = || {
            let read = |c| {
                let mut t: libc::timespec = unsafe { std::mem::zeroed() };
                unsafe { libc::clock_gettime(c, &mut t) };
                t.tv_sec as i64
            };
            read(libc::CLOCK_BOOTTIME) - read(libc::CLOCK_MONOTONIC)
        };
        let mut last = gap();
        loop {
            std::thread::sleep(std::time::Duration::from_secs(2));
            let now = gap();
            if now - last >= 5 {
                g2.rearm("woke up");
            }
            last = now;
        }
    });
    loop {
        let mut sig: libc::c_int = 0;
        if unsafe { libc::sigwait(&set, &mut sig) } == 0 && sig != libc::SIGHUP {
            break;
        }
    }
    g.shutdown();
    firewall_close()
}

#[cfg(windows)]
fn run_daemon() -> Result<(), String> {
    Err("on Windows the guard runs as a service (or use `console`)".into())
}

/// The real firewall, end to end: install the block, check it, add and
/// remove the temporary allow-all, catch a stray rule, (Linux) redirect DNS,
/// then remove everything and check it's gone. Linux: refused outside a
/// separate network namespace (`sudo unshare --net pialite-guard
/// selftest-firewall`) unless --force. Windows: the allow-all goes in right
/// after the block, so the machine keeps its network (CI runners).
fn selftest_firewall(force: bool) -> Result<(), String> {
    if !sys::is_admin() {
        return Err("needs an administrator / root".into());
    }
    #[cfg(not(windows))]
    {
        let ns = |p: &str| std::fs::read_link(p).ok();
        if !force && ns("/proc/self/ns/net") == ns("/proc/1/ns/net") {
            return Err("run it in a test network namespace: sudo unshare --net pialite-guard selftest-firewall".into());
        }
    }
    // Windows has no separate network namespace: refuse to rewrite a real
    // install's rules (review V95-04) - checked before anything is changed
    #[cfg(windows)]
    selftest_allowed(sys::service_installed(), firewall::installed(), force)?;
    let mut fails = 0;
    let mut check = |what: &str, r: Result<(), String>| match r {
        Ok(()) => println!("PASS: {what}"),
        Err(e) => {
            fails += 1;
            println!("FAIL: {what}: {e}");
        }
    };
    #[cfg(not(windows))]
    let _ = std::process::Command::new("ip").args(["link", "set", "lo", "up"]).status();
    check("start clean", firewall::uninstall());
    check("nothing installed", firewall::installed().and_then(|b| if b { Err("rules found".into()) } else { Ok(()) }));
    let apps = pia::engine_exes();
    let plan = firewall::plan(&apps, false);
    let specs = firewall::install(&plan);
    let open = firewall::open_all();
    check("block installed", specs.as_ref().map(|_| ()).map_err(|e| e.clone()));
    check("temporary allow-all added", open.as_ref().map(|_| ()).map_err(|e| e.clone()));
    let specs = specs.unwrap_or_default();
    check("rules exactly as planned", firewall::verify(&specs));
    check("block floor recognised", firewall::block_floor(&firewall::known_shapes(&apps, false, &specs)));
    #[cfg(windows)]
    check("DNS to other servers blocked by the DNS block; the guard itself gets through", windows_dns_block_test());
    #[cfg(windows)]
    check("block floor still recognised next to the DNS block", firewall::block_floor(&firewall::known_shapes(&apps, false, &specs)));
    #[cfg(not(windows))]
    {
        // a stray permit in the guard's "open" chain must be caught
        let added = std::process::Command::new("nft")
            .args(["add", "rule", "inet", firewall::nft::TABLE, "open", "accept", "comment", "\"stray\""])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let caught = firewall::verify(&specs);
        check(
            "a stray allow rule is caught",
            if added && caught.is_err() { Ok(()) } else { Err(format!("added {added}, verify said {caught:?}")) },
        );
        let _ = firewall::reset_open();
    }
    drop(open);
    check("allow-all removed, rules still as planned", firewall::verify(&specs));
    #[cfg(not(windows))]
    check("plain DNS is redirected to the proxy; other traffic is blocked", linux_traffic_test());
    check("block removed", firewall::uninstall());
    check("nothing left", firewall::installed().and_then(|b| if b { Err("rules still found".into()) } else { Ok(()) }));
    if fails > 0 {
        Err(format!("{fails} check(s) failed"))
    } else {
        println!("all firewall checks passed");
        Ok(())
    }
}

/// The firewall self-test replaces PIA Lite's rules and opens the internet for
/// a moment: only on a machine where PIA Lite isn't set up (a CI runner), or
/// with --force.
#[cfg_attr(not(any(windows, test)), allow(dead_code))]
fn selftest_allowed(service: bool, rules: Result<bool, String>, force: bool) -> Result<(), String> {
    if force {
        return Ok(());
    }
    let why = match (service, rules) {
        (true, _) => "PIA Lite's guard service is set up on this PC".to_string(),
        (false, Ok(true)) => "PIA Lite's block rules are in this PC's firewall".to_string(),
        (false, Err(e)) => format!("this PC's firewall rules could not be checked ({e})"),
        (false, Ok(false)) => return Ok(()),
    };
    Err(format!(
        "{why} - the self-test would replace them and open the internet for a moment. It is meant for test machines \
         (CI); add --force to run it here anyway. Nothing was changed."
    ))
}

/// Windows, with the temporary allow-all in place: before the DNS block a
/// program (PowerShell) gets answers from 9.9.9.9 over UDP and TCP and can
/// connect to its port 853; with the block - damaged, repaired, and rebuilt
/// with a failure injected at each stage - all three are refused (IPv4)
/// while the guard's own connection to 9.9.9.9:853 gets through; after it,
/// lookups work again.
#[cfg(windows)]
fn windows_dns_block_test() -> Result<(), String> {
    use std::time::Duration;
    let ps = |script: &str| -> bool {
        std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", script])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    };
    // a different name each time, so no cached answer counts; UDP or TCP
    let lookup_via = |name: &str, tcp: bool| {
        format!(
            "try {{ if (Resolve-DnsName {name} -Server 9.9.9.9 -Type A -DnsOnly -QuickTimeout{} -ErrorAction Stop) {{ exit 0 }} }} catch {{}}; exit 1",
            if tcp { " -TcpOnly" } else { "" }
        )
    };
    let lookup = |name: &str| lookup_via(name, false);
    const TLS: &str =
        "$c = New-Object Net.Sockets.TcpClient; try { if ($c.ConnectAsync('9.9.9.9', 853).Wait(3000)) { exit 0 } } catch {}; exit 1";
    // positive controls: each kind of traffic works before the block
    if !ps(&lookup("example.com")) {
        return Err("no answer from 9.9.9.9 even before the DNS block (no network?)".into());
    }
    if !ps(&lookup_via("iana.org", true)) {
        return Err("no answer from 9.9.9.9 over TCP even before the DNS block".into());
    }
    if !ps(TLS) {
        return Err("no connection to 9.9.9.9:853 even before the DNS block".into());
    }
    // what the DNS block must stop from another program (IPv4: hosted runners
    // have no IPv6 - IPv6 is NOT tested here). Real names that resolve, a
    // different one for every query, so no cached answer can count.
    const NAMES: [&str; 12] = [
        "ietf.org",
        "icann.org",
        "w3.org",
        "kernel.org",
        "debian.org",
        "python.org",
        "rust-lang.org",
        "mozilla.org",
        "wikipedia.org",
        "gnu.org",
        "apache.org",
        "openssl.org",
    ];
    let next = std::cell::Cell::new(0usize);
    let name = || {
        let n = NAMES[next.get() % NAMES.len()];
        next.set(next.get() + 1);
        n
    };
    let all_stopped = |when: &str| -> Result<(), String> {
        if ps(&lookup(name())) {
            return Err(format!("{when}: a program's own UDP lookup at 9.9.9.9 was NOT blocked"));
        }
        if ps(&lookup_via(name(), true)) {
            return Err(format!("{when}: a program's own TCP lookup at 9.9.9.9 was NOT blocked"));
        }
        if ps(TLS) {
            return Err(format!("{when}: a program's DNS-over-TLS connection to 9.9.9.9 was NOT blocked"));
        }
        Ok(())
    };
    firewall::dns_capture(true)?;
    let during = (|| -> Result<(), String> {
        if !firewall::dns_capture_active()? {
            return Err("the DNS block isn't there after adding it".into());
        }
        // damage it the way another program could (review F-03): a missing
        // rule, and an extra permit in its sublayer, must both be noticed and
        // repaired - the probes below then run against the repaired block
        for (how, what) in [(0u8, "a deleted IPv6 port-853 rule"), (1, "an extra permit-all in its sublayer")] {
            firewall::dns_block_damage_for_test(how)?;
            if firewall::dns_capture_active()? {
                return Err(format!("{what} was NOT noticed"));
            }
            firewall::dns_capture(true)?;
            if !firewall::dns_capture_active()? {
                return Err(format!("the DNS block wasn't repaired after {what}"));
            }
        }
        // a repair that fails - at each stage it can fail - keeps what is
        // left of the old block (review G97-03, R98-07): with its IPv6 port-853
        // rule deleted, it must still stop IPv4 UDP/53, TCP/53 and TCP/853
        for (stage, what) in
            [(1u8, "opening the firewall engine"), (2, "adding the sublayer"), (3, "adding a rule"), (4, "checking the new block")]
        {
            firewall::dns_block_damage_for_test(0)?;
            firewall::dns_block_fail_next_rebuild_for_test(stage);
            if firewall::dns_capture(true).is_ok() {
                return Err(format!("the injected failure at {what} didn't fail the rebuild"));
            }
            if firewall::dns_capture_active()? {
                return Err(format!("a damaged DNS block was reported as intact (failure at {what})"));
            }
            all_stopped(&format!("rebuild failed at {what}"))?;
            firewall::dns_capture(true)?;
            if !firewall::dns_capture_active()? {
                return Err(format!("the DNS block wasn't repaired after the failure at {what}"));
            }
        }
        all_stopped("repaired block")?;
        let addr: std::net::SocketAddr = "9.9.9.9:853".parse().map_err(|_| "address")?;
        std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(5))
            .map_err(|e| format!("the guard's own connection to 9.9.9.9:853 was blocked: {e}"))?;
        Ok(())
    })();
    let removed = firewall::dns_capture(false);
    during?;
    removed?;
    if firewall::dns_capture_active()? {
        return Err("the DNS block is still there after removing it".into());
    }
    if !ps(&lookup("example.org")) {
        return Err("lookups at 9.9.9.9 still fail after removing the DNS block".into());
    }
    Ok(())
}

/// In the test namespace: a virtual network with a default route, a fake DNS
/// server on 127.0.0.1:53, and two packets - DNS to an outside address must
/// arrive at the fake server; anything else must be refused by the block.
#[cfg(not(windows))]
fn linux_traffic_test() -> Result<(), String> {
    use std::net::UdpSocket;
    use std::time::Duration;
    for args in [
        &["link", "add", "pl0", "type", "veth", "peer", "name", "pl1"][..],
        &["addr", "add", "10.99.0.1/24", "dev", "pl0"],
        &["link", "set", "pl0", "up"],
        &["link", "set", "pl1", "up"],
        &["route", "add", "default", "dev", "pl0"],
    ] {
        let _ = std::process::Command::new("ip").args(args).status();
    }
    let server = UdpSocket::bind("127.0.0.1:53").map_err(|e| format!("fake DNS server: {e}"))?;
    server.set_read_timeout(Some(Duration::from_secs(3))).map_err(|e| e.to_string())?;
    firewall::dns_capture(true)?;
    let client = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    client.set_read_timeout(Some(Duration::from_secs(3))).map_err(|e| e.to_string())?;
    client.send_to(b"\x12\x34dns?", "192.0.2.53:53").map_err(|e| format!("sending the DNS packet: {e}"))?;
    let mut buf = [0u8; 64];
    let (n, from) = server.recv_from(&mut buf).map_err(|e| format!("the redirected DNS packet never arrived: {e}"))?;
    if &buf[..n] != b"\x12\x34dns?" {
        return Err("a different packet arrived".into());
    }
    server.send_to(b"answer", from).map_err(|e| e.to_string())?;
    let (n, src) = client.recv_from(&mut buf).map_err(|e| format!("no answer back through the redirect: {e}"))?;
    if &buf[..n] != b"answer" || src.to_string() != "192.0.2.53:53" {
        return Err(format!("the answer came back wrong (from {src})"));
    }
    // not DNS: blocked by the kill switch
    let other = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let sent = other.send_to(b"x", "10.99.0.2:9");
    let r = firewall::dns_capture(false);
    match sent {
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error() == Some(libc::EPERM) => {}
        Err(e) => return Err(format!("a non-DNS packet failed differently than expected: {e}")),
        Ok(_) => return Err("a non-DNS packet to the network was NOT blocked".into()),
    }
    r?;
    if firewall::dns_capture_active()? {
        return Err("the DNS redirect is still there after removing it".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{profile_from_page, ProfileCheck};

    #[test]
    fn profile_tri_state() {
        // review N-10: a concrete mismatch fails, a fingerprint is NOT a match
        assert!(matches!(profile_from_page("abc123", "ABC123"), ProfileCheck::Match(_)));
        assert!(matches!(profile_from_page("zzz999", "abc123"), ProfileCheck::Mismatch(_)));
        assert!(matches!(profile_from_page("", "abc123"), ProfileCheck::Mismatch(_)));
        assert!(matches!(profile_from_page("fp1a2b3c", "abc123"), ProfileCheck::Unknown(_)));
        assert!(matches!(profile_from_page("abc123", ""), ProfileCheck::Mismatch(_)));
    }

    #[cfg(not(windows))]
    #[test]
    fn check_rules_never_reads_cant_look_as_none() {
        // review V3-01
        let _g = crate::config::tests::ENV_LOCK.lock().unwrap();
        crate::firewall::fail_inspect(true);
        let r = super::check_rules();
        crate::firewall::fail_inspect(false);
        assert!(r.unwrap_err().contains("could NOT check"));
        assert!(super::check_rules().is_ok() || crate::firewall::installed() == Ok(true));
    }

    #[cfg(not(windows))]
    #[test]
    fn show_rules_fails_on_a_difference() {
        // review V4-05: CHECK-DIFF must also mean a non-zero exit
        let _g = crate::config::tests::ENV_LOCK.lock().unwrap();
        let d = crate::config::tests::temp_data("showrules");
        std::env::set_var("PIALITE_IPC_PORT", "1"); // no guard answering: use the saved settings
        let rules = crate::firewall::plan(&crate::pia::engine_exes(), false);
        crate::firewall::install(&rules).unwrap();
        crate::firewall::install_boot(&crate::firewall::boot_plan()).unwrap();
        crate::config::save(&crate::config::Config { mode: super::BlockMode::Always, ..Default::default() }).unwrap();
        assert!(super::show_rules(false).is_ok(), "rules as planned");
        assert!(
            crate::firewall::tamper_value() || {
                crate::firewall::tamper_action();
                true
            }
        );
        assert!(super::show_rules(false).is_err(), "a changed rule -> exit 1");
        crate::firewall::uninstall().unwrap();
        assert!(super::show_rules(false).is_err(), "block on but no rules -> exit 1");
        crate::config::save(&crate::config::Config::default()).unwrap();
        assert!(super::show_rules(false).is_ok(), "block off and no rules -> fine");
        crate::firewall::install_boot(&crate::firewall::boot_plan()).unwrap();
        assert!(super::show_rules(false).is_err(), "block off but boot-time rules left in Windows -> exit 1 (review F51-03)");
        crate::firewall::uninstall().unwrap();
        std::env::remove_var("PIALITE_IPC_PORT");
        let _ = std::fs::remove_dir_all(d);
    }

    /// Review V60-04: guard not running, no settings, no rules -> nothing is
    /// wanted, exit 0; no settings but rules in Windows -> they count.
    #[test]
    fn show_rules_offline_without_settings() {
        let _g = crate::config::tests::ENV_LOCK.lock().unwrap();
        let d = crate::config::tests::temp_data("showrules-clean");
        std::env::set_var("PIALITE_IPC_PORT", "1"); // no guard answering
        crate::firewall::uninstall().unwrap();
        assert!(super::show_rules(false).is_ok(), "clean PC: none wanted, none there");
        crate::firewall::install(&crate::firewall::plan(&crate::pia::engine_exes(), false)).unwrap();
        crate::firewall::install_boot(&crate::firewall::boot_plan()).unwrap();
        assert!(super::show_rules(false).is_ok(), "rules but no settings: protective setting assumed, rules as planned");
        crate::firewall::uninstall().unwrap();
        std::env::remove_var("PIALITE_IPC_PORT");
        let _ = std::fs::remove_dir_all(d);
    }

    /// Review F51-03: mode x boot-time setting x (present / missing / changed)
    /// for both kinds of rule - exit status (all checks ok) must follow
    /// "wanted" exactly, and "wanted" comes from settings, never from what
    /// was observed.
    #[test]
    fn show_rules_truth_table() {
        use super::{rule_checks, want_from_saved, want_from_status, BlockMode, GuardStatus};
        let verdict = |v: Option<bool>| move || if v == Some(true) { Ok(()) } else { Err("changed".to_string()) };
        for mode in [BlockMode::Off, BlockMode::Startup, BlockMode::Always] {
            for boot_pref in [true, false] {
                for strict in [false, true] {
                    let c = crate::config::Config { mode, boot_time_rules: boot_pref, ..Default::default() };
                    let w = want_from_saved(&c, strict, "test");
                    let rules = strict || mode != BlockMode::Off;
                    assert_eq!((w.rules, w.boot), (rules, rules && boot_pref), "{mode:?} boot {boot_pref} strict {strict}");
                    // None = missing, Some(true) = present as planned, Some(false) = present but changed
                    for p in [None, Some(true), Some(false)] {
                        for b in [None, Some(true), Some(false)] {
                            let checks = rule_checks(&w, p.is_some(), b.is_some(), verdict(p), verdict(b));
                            let all_ok = checks.iter().all(|(_, r)| r.is_ok());
                            let want_ok = (if w.rules { p == Some(true) } else { p.is_none() })
                                && (if w.boot { b == Some(true) } else { b.is_none() });
                            assert_eq!(all_ok, want_ok, "{mode:?} boot {boot_pref} strict {strict}: persistent {p:?} boot {b:?}");
                        }
                    }
                }
            }
        }
        let ok = || Ok(());
        // the running guard's own statement decides
        let st = GuardStatus {
            mode: BlockMode::Always,
            boot_rules: false,
            rules_wanted: Some(true),
            boot_rules_wanted: Some(false),
            effective_mode: Some(BlockMode::Always),
            ..Default::default()
        };
        let w = want_from_status(&st).unwrap();
        assert!(w.rules && !w.boot);
        assert!(
            rule_checks(&w, true, false, ok, ok).iter().all(|(_, r)| r.is_ok()),
            "Always with boot-time rules off: no false difference"
        );
        let st = GuardStatus {
            rules_wanted: Some(false),
            boot_rules_wanted: Some(false),
            effective_mode: Some(BlockMode::Off),
            ..Default::default()
        };
        let w = want_from_status(&st).unwrap();
        assert!(rule_checks(&w, false, true, ok, ok).iter().any(|(_, r)| r.is_err()), "Off with leftover boot-time rules: a difference");
        assert_eq!(want_from_status(&GuardStatus::default()), None, "an older guard doesn't say what it wants");
    }

    #[test]
    fn selftest_refuses_a_real_install() {
        // review V95-04: decided before any rule is touched
        assert!(super::selftest_allowed(false, Ok(false), false).is_ok(), "a clean test machine");
        assert!(super::selftest_allowed(true, Ok(false), false).unwrap_err().contains("guard service is set up"));
        assert!(super::selftest_allowed(false, Ok(true), false).unwrap_err().contains("Nothing was changed"));
        assert!(super::selftest_allowed(false, Err("engine".into()), false).unwrap_err().contains("could not be checked"));
        assert!(super::selftest_allowed(true, Ok(true), true).is_ok(), "--force");
    }

    #[test]
    fn redirect_targets() {
        assert_eq!(super::redirect_target("https://x1y2.test.nextdns.io/").unwrap(), ("x1y2.test.nextdns.io".into(), "/".into()));
        assert_eq!(super::redirect_target("https://test.nextdns.io:443/a?b").unwrap(), ("test.nextdns.io".into(), "/a?b".into()));
        assert!(super::redirect_target("http://x.test.nextdns.io/").is_err(), "https only");
        assert!(super::redirect_target("https://evil.example/").is_err(), "nextdns.io only");
        assert!(super::redirect_target("https://nextdns.io.evil.example/").is_err());
    }
}
