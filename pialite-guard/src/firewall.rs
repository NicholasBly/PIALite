//! The internet block: Windows Filtering Platform (WFP) rules for outgoing traffic.
//!
//! Three kinds of rules, so there is no gap from power-on (audit P0-02):
//!  * boot-time rules (FWPM_FILTER_FLAG_BOOTTIME): enforced by the network
//!    driver (tcpip.sys) as soon as it starts, until Windows' filtering engine
//!    (BFE) is up. Only loopback and DHCP get out. PIA isn't running yet then
//!    anyway (it needs BFE).
//!  * persistent rules: loaded by BFE when it starts. They let through what
//!    PIA's own "always on" kill switch does - loopback, PIA's own programs,
//!    DHCP and, if PIA's "Allow LAN" is on, the local network.
//!    Microsoft describes the switch from boot-time to persistent filters as
//!    atomic ("if a provider has both a boot-time and a persistent filter,
//!    there will never be a window when neither is in effect"). Our boot-time
//!    filters use built-in objects only (no provider), so for this exact setup
//!    a gap-free switch is the DESIGN EXPECTATION, to be confirmed by a boot
//!    capture on the real PC - not a proven guarantee (review V4-08).
//!  * a temporary "allow all" in the guard's own WFP session, added only while
//!    the state machine (policy.rs) says so. If the service dies, Windows drops
//!    it by itself and the block is back - it fails closed.
//!
//! Every WFP filter has AT MOST ONE condition of each kind: Microsoft documents
//! that conditions in one filter are ANDed (OR only on Windows 7), so each
//! allowed program and each local-network range is its own filter (review N-01).
//!
//! What Windows really holds is checked against the plan, filter by filter:
//! layer, action, flags, weight (type and value), provider, sublayer, and every
//! condition's field, match type and VALUE (the program's app ID bytes, the
//! address range, the port) - plus anything extra in our key ranges or under
//! our provider on the two layers we use (outbound connect, ALE_AUTH_CONNECT
//! v4/v6 - other layers are not searched), and the provider and sublayer
//! objects themselves: flags, weight, owner (review N-08, N-09, V3-05, V4-07,
//! V4-13). `installed()` tells "none" apart from "couldn't look" (V3-01).

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Cond {
    Loopback,
    /// One program (full path).
    App(String),
    Dhcp,
    RemotePort(u16),
    /// IPv4 range (address, prefix length) - IPv4 layer only.
    Subnet4([u8; 4], u8),
    /// IPv6 range (first 16 bits, prefix length) - IPv6 layer only.
    Subnet6(u16, u8),
    /// Linux: traffic from processes of this group (PIA's daemon runs with
    /// group "piavpn" - how PIA's own Linux kill switch lets it out).
    Group(u32),
    /// Linux: packets carrying this firewall mark (PIA's kernel WireGuard
    /// packets have no process; PIA marks them 12817 + 2).
    Mark(u32),
    All,
}

impl Cond {
    /// Does this rule exist on the IPv4 (false) / IPv6 (true) layer?
    pub fn applies(&self, v6: bool) -> bool {
        match self {
            Cond::Subnet4(..) => !v6,
            Cond::Subnet6(..) => v6,
            _ => true,
        }
    }
    /// How many WFP conditions the filter carries.
    #[cfg_attr(not(any(test, windows)), allow(dead_code))]
    pub fn conditions(&self) -> u32 {
        match self {
            Cond::All => 0,
            Cond::Dhcp => 3, // protocol AND local port AND remote port (different fields)
            _ => 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub weight: u8,
    pub permit: bool,
    pub cond: Cond,
    pub name: String,
}

fn rule(weight: u8, permit: bool, cond: Cond, name: impl Into<String>) -> Rule {
    Rule { weight, permit, cond, name: name.into() }
}

pub const LAN_V4: [([u8; 4], u8); 6] = [
    ([10, 0, 0, 0], 8),
    ([172, 16, 0, 0], 12),
    ([192, 168, 0, 0], 16),
    ([169, 254, 0, 0], 16),
    ([224, 0, 0, 0], 4),
    ([255, 255, 255, 255], 32),
];
pub const LAN_V6: [(u16, u8); 3] = [(0xfc00, 7), (0xfe80, 10), (0xff00, 8)];

/// The persistent rule set (outgoing). Highest weight wins inside our sublayer.
pub fn plan(apps: &[String], allow_lan: bool) -> Vec<Rule> {
    let mut r = vec![rule(15, true, Cond::Loopback, "allow loopback (local DNS proxy, apps talking to themselves)")];
    for a in apps {
        // Linux permits come as "gid:N" / "mark:N" (see pia::engine_exes)
        if let Some(g) = a.strip_prefix("gid:").and_then(|n| n.parse().ok()) {
            r.push(rule(14, true, Cond::Group(g), format!("allow PIA's daemon (group id {g})")));
            continue;
        }
        if let Some(m) = a.strip_prefix("mark:").and_then(|n| n.parse().ok()) {
            r.push(rule(14, true, Cond::Mark(m), format!("allow PIA's WireGuard packets (mark {m})")));
            continue;
        }
        let file = a.rsplit(['\\', '/']).next().unwrap_or(a);
        r.push(rule(14, true, Cond::App(a.clone()), format!("allow PIA program {file}")));
    }
    r.push(rule(13, true, Cond::Dhcp, "allow DHCP (getting an IP address)"));
    if allow_lan {
        r.push(rule(12, false, Cond::RemotePort(53), "block plain DNS to the LAN/router"));
        for (a, p) in LAN_V4 {
            r.push(rule(11, true, Cond::Subnet4(a, p), format!("allow local network {}.{}.{}.{}/{p}", a[0], a[1], a[2], a[3])));
        }
        for (a, p) in LAN_V6 {
            r.push(rule(11, true, Cond::Subnet6(a, p), format!("allow local network {a:x}::/{p}")));
        }
    }
    r.push(rule(0, false, Cond::All, "block everything else until the VPN connects"));
    r
}

/// Boot-time rules (before BFE starts): loopback + DHCP, everything else blocked.
pub fn boot_plan() -> Vec<Rule> {
    vec![
        rule(15, true, Cond::Loopback, "boot: allow loopback"),
        rule(13, true, Cond::Dhcp, "boot: allow DHCP"),
        rule(0, false, Cond::All, "boot: block everything before the firewall engine starts"),
    ]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Persistent,
    BootTime,
}

/// What one WFP filter must look like. Index = position in its key range.
/// `cond` is turned into the exact WFP conditions (with values) when checking.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilterSpec {
    pub index: u32,
    pub kind: Kind,
    pub v6: bool,
    pub permit: bool,
    pub weight: u8,
    pub cond: Cond,
}

/// The exact filters a rule set turns into (IPv4 layer first, then IPv6).
pub fn specs(rules: &[Rule], kind: Kind) -> Vec<FilterSpec> {
    let mut out = vec![];
    for v6 in [false, true] {
        for r in rules.iter().filter(|r| r.cond.applies(v6)) {
            out.push(FilterSpec { index: out.len() as u32, kind, v6, permit: r.permit, weight: r.weight, cond: r.cond.clone() });
        }
    }
    out
}

/// Rules that may legitimately be in Windows when a refresh fails: the plan,
/// the same plan with the other Allow LAN choice, and the last set the guard
/// itself verified (review FINAL-01). Anything else under PIA Lite's name
/// makes the floor check fail.
pub fn known_shapes(apps: &[String], allow_lan: bool, previous: &[FilterSpec]) -> Vec<FilterSpec> {
    let mut out = specs(&plan(apps, allow_lan), Kind::Persistent);
    out.extend(specs(&plan(apps, !allow_lan), Kind::Persistent));
    out.extend(previous.iter().filter(|f| f.kind == Kind::Persistent).cloned());
    out
}

/// Is a temporary (non-persistent) permit-everything filter under PIA Lite's
/// name really the guard's own allow-all? Only if this guard added it (its
/// id is one the guard holds right now) and it has exactly that shape: our
/// sublayer, weight 15, no conditions, no weakening flags (review V63-05).
/// Anything else is a stray permit that could undo the block.
#[cfg_attr(not(any(test, windows)), allow(dead_code))]
pub fn is_own_allow_all(id: u64, owned: &[u64], in_our_sublayer: bool, weight: Option<u8>, conditions: u32, flags_ok: bool) -> bool {
    owned.contains(&id) && in_our_sublayer && weight == Some(15) && conditions == 0 && flags_ok
}

/// Ids of the allow-all filters this guard currently holds (added by
/// open_all, forgotten when that value is dropped).
#[cfg_attr(any(test, not(any(windows, target_os = "linux"))), allow(dead_code))]
pub static OWN_ALLOW_ALL: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());

/// Same rule apart from its position (index).
#[cfg_attr(not(test), allow(dead_code))]
pub fn same_shape(a: &FilterSpec, b: &FilterSpec) -> bool {
    a.kind == b.kind && a.v6 == b.v6 && a.permit == b.permit && a.weight == b.weight && a.cond == b.cond
}

/// Keys per range. Persistent rules need 2 x (1 + apps + 1 + 1) + 9 LAN.
#[cfg_attr(not(windows), allow(dead_code))]
pub const MAX_FILTERS: u32 = 128;

#[cfg_attr(not(windows), allow(dead_code))]
pub fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

/// show-rules order: boot-time rules, then persistent ones, then anything
/// else; by rule number, so #2 comes before #10.
pub fn sort_rule_lines(lines: &mut [String]) {
    lines.sort_by_key(|l| {
        let group = if l.starts_with("boot-time") {
            0
        } else if l.starts_with("persistent") {
            1
        } else {
            2
        };
        let n = if group < 2 {
            l.split_once('#').and_then(|(_, r)| r.split_whitespace().next()).and_then(|d| d.parse::<u32>().ok())
        } else {
            None
        };
        (group, n.unwrap_or(u32::MAX), l.clone())
    });
}

#[cfg(all(target_os = "linux", not(test)))]
pub use linux::*;
#[cfg(any(test, not(any(windows, target_os = "linux"))))]
pub use stub::*;
#[cfg(all(windows, not(test)))]
pub use win::*;

/// Linux: the same rules as nftables rules, one per filter, each tagged with
/// a comment ("pialite:p:N") so what the kernel holds can be checked rule by
/// rule. Pure text - tested on every platform.
#[cfg_attr(any(test, not(target_os = "linux")), allow(dead_code))]
pub mod nft {
    use super::{Cond, FilterSpec, Kind};

    pub const TABLE: &str = "pialite";
    /// Scratch table (no hook: no effect on traffic) where the expected rules
    /// are loaded so nftables writes them in ITS normal form - compared with
    /// the live table, the check works with every nftables version.
    pub const REF_TABLE: &str = "pialite_ref";

    pub fn comment(spec: &FilterSpec) -> String {
        format!("pialite:{}:{}", if spec.kind == Kind::Persistent { "p" } else { "b" }, spec.index)
    }

    /// The nftables expression for one filter (without the verdict).
    pub fn cond_expr(cond: &Cond, v6: bool) -> Result<String, String> {
        let fam = if v6 { "ipv6" } else { "ipv4" };
        Ok(match cond {
            Cond::All => format!("meta nfproto {fam}"),
            // to an address of this machine - never leaves it. Not `oifname
            // "lo"`: a DNS packet redirected to the proxy keeps its original
            // outgoing interface in this hook (found by selftest-firewall)
            Cond::Loopback => format!("meta nfproto {fam} fib daddr type local"),
            Cond::Dhcp if v6 => "meta nfproto ipv6 udp sport 546 udp dport 547".into(),
            Cond::Dhcp => "meta nfproto ipv4 udp sport 68 udp dport 67".into(),
            Cond::RemotePort(p) => format!("meta nfproto {fam} meta l4proto {{ tcp, udp }} th dport {p}"),
            Cond::Subnet4(a, p) => format!("ip daddr {}.{}.{}.{}/{p}", a[0], a[1], a[2], a[3]),
            Cond::Subnet6(first, p) => format!("ip6 daddr {first:x}::/{p}"),
            Cond::Group(g) => format!("meta nfproto {fam} meta skgid {g}"),
            Cond::Mark(m) => format!("meta nfproto {fam} meta mark {m}"),
            Cond::App(path) => return Err(format!("program rules ({path}) are Windows-only")),
        })
    }

    /// One rule, as written to nftables.
    pub fn rule_text(spec: &FilterSpec) -> Result<String, String> {
        let verdict = if spec.permit { "accept" } else { "reject with icmpx admin-prohibited" };
        Ok(format!("{} {verdict} comment \"{}\"", cond_expr(&spec.cond, spec.v6)?, comment(spec)))
    }

    /// Rules Linux needs that Windows' connect layer never sees: IPv6
    /// neighbour discovery (finding the router and neighbours), and the jump
    /// into the "open" chain where the guard's temporary allow-all lives.
    pub const PREAMBLE: [&str; 2] = [
        "icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept comment \"pialite:ndp\"",
        "jump open comment \"pialite:open\"",
    ];

    /// The whole change, as one nftables transaction (all or nothing). Only
    /// the "out" chain is replaced: the allow-all in "open" stays as it is
    /// (like the guard's temporary WFP session on Windows). `hook`: the live
    /// table (hooked into outgoing traffic) or the scratch reference table.
    pub fn script(specs: &[FilterSpec], table: &str, hook: bool) -> Result<String, String> {
        let mut rules: Vec<&FilterSpec> = specs.iter().collect();
        // highest weight first (WFP: highest weight wins; nftables: first match)
        rules.sort_by(|a, b| b.weight.cmp(&a.weight).then(a.index.cmp(&b.index)));
        let chain_def = if hook { " { type filter hook output priority filter; policy accept; }" } else { "" };
        let mut s = format!(
            "add table inet {table}\nadd chain inet {table} out{chain_def}\nadd chain inet {table} open\nflush chain inet {table} out\n"
        );
        let mut preamble_done = false;
        for r in rules {
            // loopback (weight 15) first, then the preamble, like WFP's weight 15 allow-all
            if !preamble_done && r.weight < 15 {
                for p in PREAMBLE {
                    s.push_str(&format!("add rule inet {table} out {p}\n"));
                }
                preamble_done = true;
            }
            s.push_str(&format!("add rule inet {table} out {}\n", rule_text(r)?));
        }
        if !preamble_done {
            for p in PREAMBLE {
                s.push_str(&format!("add rule inet {table} out {p}\n"));
            }
        }
        Ok(s)
    }

    /// The rules of one chain from `nft -n -a list table ...`: (text without
    /// the handle, handle). Header lines (type/hook/policy) start with "type".
    pub fn chain_rules(listing: &str, chain: &str) -> Option<Vec<(String, u64)>> {
        let mut out = vec![];
        let mut inside = false;
        let mut found = false;
        for line in listing.lines() {
            let t = line.trim();
            if t.starts_with("chain ") {
                inside = t.trim_start_matches("chain ").split_whitespace().next() == Some(chain);
                found |= inside;
                continue;
            }
            if !inside || t.is_empty() || t.starts_with("type ") {
                continue; // the chain's header (type, hook, priority, policy)
            }
            if t == "}" {
                inside = false;
                continue;
            }
            let (body, handle) = match t.rsplit_once(" # handle ") {
                Some((b, h)) => (b.trim().to_string(), h.trim().parse().unwrap_or(0)),
                None => (t.to_string(), 0),
            };
            out.push((body, handle));
        }
        found.then_some(out)
    }

    /// The comment of a listed rule ("" if none).
    pub fn comment_of(rule: &str) -> &str {
        rule.rsplit_once("comment \"").map(|(_, c)| c.trim_end_matches('"')).unwrap_or("")
    }

    /// Linux encrypted DNS: a table of its own, independent of the block.
    pub const DNS_TABLE: &str = "pialite_dns";
    pub const DNS_MARKER: &str = "pialite:dns-redirect";

    /// Every plain DNS query (port 53) a program sends goes to the guard's
    /// proxy on 127.0.0.1:53 instead - whatever server the system or PIA
    /// configured, so nothing depends on how this distribution manages DNS.
    /// Left alone: loopback destinations (the proxy itself, systemd-resolved's
    /// 127.0.0.53 stub) and PIA's own daemon (group `gid`). IPv6 DNS is
    /// refused (PIA blocks IPv6 anyway; resolvers then use IPv4). One
    /// transaction: the old table, if any, is replaced as a whole.
    pub fn dns_capture_script(gid: Option<u32>) -> String {
        let t = DNS_TABLE;
        let mut s = format!(
            "add table inet {t}\ndelete table inet {t}\nadd table inet {t}\n\
             add chain inet {t} nat {{ type nat hook output priority -100; policy accept; }}\n\
             add chain inet {t} filter {{ type filter hook output priority -1; policy accept; }}\n"
        );
        if let Some(g) = gid {
            s += &format!("add rule inet {t} nat meta skgid {g} return\n");
            s += &format!("add rule inet {t} filter meta skgid {g} return\n");
        }
        s += &format!("add rule inet {t} nat ip daddr 127.0.0.0/8 return\n");
        s += &format!(
            "add rule inet {t} nat meta nfproto ipv4 meta l4proto {{ tcp, udp }} th dport 53 redirect to :53 comment \"{DNS_MARKER}\"\n"
        );
        s += &format!(
            "add rule inet {t} filter meta nfproto ipv6 ip6 daddr != ::1 meta l4proto {{ tcp, udp }} th dport 53 reject with icmpx port-unreachable comment \"pialite:dns-no-v6\"\n"
        );
        s
    }
}

#[cfg(any(test, not(any(windows, target_os = "linux"))))]
mod stub {
    //! In-memory stand-in so the guard can be built and tested on Linux,
    //! including tampering and failure injection.
    use super::{specs, FilterSpec, Kind, Rule};
    use std::sync::Mutex;

    struct State {
        persistent: Vec<FilterSpec>,
        boot: Vec<FilterSpec>,
        open: usize,
        fail_installs: usize,
        fail_inspect: bool,
        fail_next_uninstall: bool,
        installs: usize,
        stray_permit: bool,
    }
    static S: Mutex<State> = Mutex::new(State {
        persistent: vec![],
        boot: vec![],
        open: 0,
        fail_installs: 0,
        fail_inspect: false,
        fail_next_uninstall: false,
        installs: 0,
        stray_permit: false,
    });

    pub fn install(rules: &[Rule]) -> Result<Vec<FilterSpec>, String> {
        let mut s = S.lock().unwrap();
        if s.fail_installs > 0 {
            s.fail_installs -= 1;
            return Err("injected install failure".into());
        }
        s.persistent = specs(rules, Kind::Persistent);
        s.installs += 1;
        Ok(s.persistent.clone())
    }
    pub fn install_boot(rules: &[Rule]) -> Result<Vec<FilterSpec>, String> {
        let mut s = S.lock().unwrap();
        s.boot = specs(rules, Kind::BootTime);
        Ok(s.boot.clone())
    }
    pub fn remove_boot() -> Result<(), String> {
        S.lock().unwrap().boot.clear();
        Ok(())
    }
    pub fn uninstall() -> Result<(), String> {
        let mut s = S.lock().unwrap();
        if std::mem::take(&mut s.fail_next_uninstall) {
            return Err("injected uninstall failure".into());
        }
        s.persistent.clear();
        s.boot.clear();
        Ok(())
    }
    /// Ok(false) only when it was possible to look and nothing is there.
    pub fn installed() -> Result<bool, String> {
        let s = S.lock().unwrap();
        if s.fail_inspect {
            return Err("injected: firewall engine not reachable".into());
        }
        Ok(!s.persistent.is_empty() || !s.boot.is_empty())
    }
    pub fn diagnose() -> String {
        "test stub".into()
    }
    pub fn reset_open() -> Result<(), String> {
        Ok(())
    }
    static DNS_CAPTURE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static DNS_FAIL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    static DNS_INSPECT_FAIL: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    pub fn dns_capture(on: bool) -> Result<(), String> {
        if DNS_FAIL.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("injected: the firewall refused the DNS rules".into());
        }
        DNS_CAPTURE.store(on, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    pub fn dns_capture_active() -> Result<bool, String> {
        if DNS_INSPECT_FAIL.load(std::sync::atomic::Ordering::SeqCst) {
            return Err("injected: firewall engine not reachable".into());
        }
        Ok(DNS_CAPTURE.load(std::sync::atomic::Ordering::SeqCst))
    }
    #[allow(dead_code)]
    pub fn dns_block_fail_next_rebuild_for_test(_stage: u8) {
        DNS_FAIL.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    #[allow(dead_code)]
    pub fn dns_block_damage_for_test(_how: u8) -> Result<(), String> {
        DNS_CAPTURE.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
    /// Tests: every DNS block/redirect change fails / every check fails.
    pub fn fail_dns_capture(on: bool) {
        DNS_FAIL.store(on, std::sync::atomic::Ordering::SeqCst);
    }
    pub fn fail_dns_inspect(on: bool) {
        DNS_INSPECT_FAIL.store(on, std::sync::atomic::Ordering::SeqCst);
    }
    /// The block-everything floor (review FINAL-01): a persistent, unconditional
    /// block on BOTH IPv4 and IPv6, and nothing under PIA Lite's name that isn't
    /// one of `known` (by shape).
    pub fn block_floor(known: &[FilterSpec]) -> Result<(), String> {
        let s = S.lock().unwrap();
        if s.fail_inspect {
            return Err("injected: firewall engine not reachable".into());
        }
        if s.stray_permit {
            return Err("a temporary permit in PIA Lite's sublayer that the guard didn't add".into());
        }
        for v6 in [false, true] {
            let fam = if v6 { "IPv6" } else { "IPv4" };
            if !s.persistent.iter().any(|f| f.v6 == v6 && !f.permit && f.weight == 0 && f.cond == super::Cond::All) {
                return Err(format!("no persistent block-everything rule for {fam}"));
            }
        }
        match s.persistent.iter().find(|f| !known.iter().any(|k| super::same_shape(f, k))) {
            Some(f) => Err(format!("an unrecognised PIA Lite rule (#{})", f.index)),
            None => Ok(()),
        }
    }
    pub fn startup_report(_plan: &[Rule]) -> String {
        let s = S.lock().unwrap();
        format!("found at start, before any change (test stub): {} persistent rules; {} boot-time rules", s.persistent.len(), s.boot.len())
    }
    /// Same line starts as the Windows version ("persistent #n", "boot-time  #n").
    pub fn describe() -> Result<Vec<String>, String> {
        let s = S.lock().unwrap();
        let line = |f: &FilterSpec| {
            let kind = if f.kind == Kind::Persistent { "persistent" } else { "boot-time " };
            format!(
                "{kind} #{:<2} {} {} w={} {:?}",
                f.index,
                if f.v6 { "v6" } else { "v4" },
                if f.permit { "PERMIT" } else { "BLOCK" },
                f.weight,
                f.cond
            )
        };
        let mut out: Vec<String> = s.persistent.iter().chain(s.boot.iter()).map(line).collect();
        super::sort_rule_lines(&mut out);
        Ok(out)
    }
    pub fn verify(expected: &[FilterSpec]) -> Result<(), String> {
        let s = S.lock().unwrap();
        let have = if expected.first().map(|f| f.kind) == Some(Kind::BootTime) { &s.boot } else { &s.persistent };
        if have.as_slice() == expected {
            Ok(())
        } else {
            Err("rules in Windows differ from the plan".into())
        }
    }
    pub struct OpenAll;
    impl Drop for OpenAll {
        fn drop(&mut self) {
            S.lock().unwrap().open -= 1;
        }
    }
    pub fn open_all() -> Result<OpenAll, String> {
        S.lock().unwrap().open += 1;
        Ok(OpenAll)
    }

    #[cfg(test)]
    pub fn tamper_action() {
        if let Some(f) = S.lock().unwrap().persistent.last_mut() {
            f.permit = !f.permit; // e.g. block-all turned into allow-all, same key
        }
    }
    /// Same key, same number of conditions, different value (e.g. a program
    /// swapped or a network range widened) - review V3-05.
    #[cfg(test)]
    #[cfg_attr(windows, allow(dead_code))] // used by Unix-only tests
    pub fn tamper_value() -> bool {
        let mut s = S.lock().unwrap();
        for f in s.persistent.iter_mut() {
            match &mut f.cond {
                super::Cond::Subnet4(_, p) => *p -= 1,
                super::Cond::App(path) => path.push_str(".other"),
                super::Cond::RemotePort(port) => *port += 1,
                _ => continue,
            }
            return true;
        }
        false
    }
    /// Tests: someone else's temporary permit-everything in our sublayer.
    #[cfg(test)]
    pub fn set_stray_permit(on: bool) {
        S.lock().unwrap().stray_permit = on;
    }
    /// Tests: put exactly these rules "in Windows".
    #[cfg(test)]
    pub fn set_rules(persistent: Vec<FilterSpec>, boot: Vec<FilterSpec>) {
        let mut s = S.lock().unwrap();
        s.persistent = persistent;
        s.boot = boot;
    }
    #[cfg(test)]
    pub fn rules() -> (Vec<FilterSpec>, Vec<FilterSpec>) {
        let s = S.lock().unwrap();
        (s.persistent.clone(), s.boot.clone())
    }
    #[cfg(test)]
    #[cfg_attr(windows, allow(dead_code))] // used by Unix-only tests
    pub fn fail_next_uninstall() {
        S.lock().unwrap().fail_next_uninstall = true;
    }
    #[cfg(test)]
    pub fn install_count() -> usize {
        S.lock().unwrap().installs
    }
    #[cfg(test)]
    pub fn fail_inspect(on: bool) {
        S.lock().unwrap().fail_inspect = on;
    }
    #[cfg(test)]
    pub fn fail_next_install() {
        fail_installs(1);
    }
    /// Tests: the next `n` installs fail (0 = none) - also the guard's own
    /// background retries, so a test can look at the state after a failure.
    #[cfg(test)]
    pub fn fail_installs(n: usize) {
        S.lock().unwrap().fail_installs = n;
    }
    #[cfg(test)]
    pub fn open_count() -> usize {
        S.lock().unwrap().open
    }
}

/// Linux backend: nftables (table "inet pialite"). Same API as the Windows
/// one. The ruleset is also saved to the data folder; the systemd unit
/// pialite-boot.service loads it before the network starts (the Linux
/// counterpart of the boot-time rules). The allow-all lives in chain "open"
/// and is removed when the guard stops - systemd runs
/// `pialite-guard firewall-close` after the service ends, also after a crash.
#[cfg(all(target_os = "linux", not(test)))]
mod linux {
    use super::{nft, specs, FilterSpec, Kind, Rule};
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::{Command, Stdio};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    const BOOT_UNIT: &str = "pialite-boot.service";

    fn nft_bin() -> Result<&'static str, String> {
        for p in ["/usr/sbin/nft", "/sbin/nft", "/usr/bin/nft", "/bin/nft"] {
            if std::path::Path::new(p).is_file() {
                return Ok(p);
            }
        }
        Err("nftables (the 'nft' command) is not installed".into())
    }

    /// Run a program with a time limit; stdout on success, stderr as the error.
    fn run(prog: &str, args: &[&str], input: Option<&str>) -> Result<String, String> {
        let mut c = Command::new(prog);
        c.args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(if input.is_some() { Stdio::piped() } else { Stdio::null() });
        let mut child = c.spawn().map_err(|e| format!("{prog}: {e}"))?;
        if let Some(text) = input {
            if let Some(mut si) = child.stdin.take() {
                si.write_all(text.as_bytes()).map_err(|e| format!("{prog}: {e}"))?;
            }
        }
        let until = Instant::now() + Duration::from_secs(15);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < until => std::thread::sleep(Duration::from_millis(10)),
                Ok(None) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!("{prog} did not finish within 15 s"));
                }
                Err(e) => return Err(format!("{prog}: {e}")),
            }
        }
        let out = child.wait_with_output().map_err(|e| format!("{prog}: {e}"))?;
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        } else {
            let err = String::from_utf8_lossy(&out.stderr);
            Err(format!("{prog} {}: {}", args.join(" "), err.lines().find(|l| !l.trim().is_empty()).unwrap_or("failed")))
        }
    }

    fn nft(args: &[&str], input: Option<&str>) -> Result<String, String> {
        run(nft_bin()?, args, input)
    }

    /// `nft -n -a list table inet NAME`; None = no such table.
    fn list(table: &str) -> Result<Option<String>, String> {
        match nft(&["-n", "-a", "list", "table", "inet", table], None) {
            Ok(t) => Ok(Some(t)),
            Err(e) if e.contains("No such file or directory") || e.contains("does not exist") => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn saved_path() -> PathBuf {
        crate::config::data_dir().join("firewall.nft")
    }

    fn systemctl(args: &[&str]) -> Result<String, String> {
        for p in ["/usr/bin/systemctl", "/bin/systemctl"] {
            if std::path::Path::new(p).is_file() {
                return run(p, args, None);
            }
        }
        Err("systemd (systemctl) not found".into())
    }

    fn boot_enabled() -> bool {
        systemctl(&["is-enabled", BOOT_UNIT]).map(|o| o.trim() == "enabled").unwrap_or(false)
    }

    fn write_private(path: &PathBuf, text: &str) -> Result<(), String> {
        use std::os::unix::fs::OpenOptionsExt;
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        let tmp = path.with_extension("tmp");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)
            .map_err(|e| format!("{}: {e}", tmp.display()))?;
        f.write_all(text.as_bytes()).and_then(|_| f.sync_all()).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// How nftables writes `expected` (loaded into the scratch table, which
    /// has no hook and so no effect on traffic). Cached per rule set.
    fn canonical(expected: &[FilterSpec]) -> Result<Vec<String>, String> {
        static CACHE: Mutex<Option<(Vec<FilterSpec>, Vec<String>)>> = Mutex::new(None);
        if let Some((k, v)) = CACHE.lock().unwrap().as_ref() {
            if k.as_slice() == expected {
                return Ok(v.clone());
            }
        }
        let t = nft::REF_TABLE;
        let script = format!("add table inet {t}\ndelete table inet {t}\n{}", nft::script(expected, t, false)?);
        nft(&["-f", "-"], Some(&script))?;
        let listing = list(t);
        let _ = nft(&["delete", "table", "inet", t], None);
        let listing = listing?.ok_or("the reference table vanished")?;
        let rules: Vec<String> =
            nft::chain_rules(&listing, "out").ok_or("reference table has no chain")?.into_iter().map(|(b, _)| b).collect();
        *CACHE.lock().unwrap() = Some((expected.to_vec(), rules.clone()));
        Ok(rules)
    }

    fn strip_comment(rule: &str) -> &str {
        rule.rsplit_once(" comment \"").map(|(b, _)| b).unwrap_or(rule)
    }

    pub fn install(rules: &[Rule]) -> Result<Vec<FilterSpec>, String> {
        let sp = specs(rules, Kind::Persistent);
        let script = nft::script(&sp, nft::TABLE, true)?;
        nft(&["-f", "-"], Some(&script))?;
        // the same rules for the next boot (loaded before the network starts)
        write_private(&saved_path(), &script)?;
        Ok(sp)
    }

    pub fn install_boot(rules: &[Rule]) -> Result<Vec<FilterSpec>, String> {
        if !saved_path().is_file() {
            return Err("no saved ruleset yet for the boot unit".into());
        }
        systemctl(&["enable", BOOT_UNIT]).map_err(|e| format!("boot protection unit: {e}"))?;
        Ok(specs(rules, Kind::BootTime))
    }

    pub fn remove_boot() -> Result<(), String> {
        match systemctl(&["disable", BOOT_UNIT]) {
            Ok(_) => Ok(()),
            Err(e) if e.contains("not found") || e.contains("does not exist") => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Order (review F-02): the boot unit off, then the saved rules, and the
    /// live rules LAST - a failure before that leaves the PC protected, for
    /// the caller to recover (teardown starts the guard again).
    pub fn uninstall() -> Result<(), String> {
        // a failed disable leaves the saved rules, so installed() still says "present" (V95-12)
        remove_boot().map_err(|e| format!("could not disable the boot protection unit: {e}"))?;
        match std::fs::remove_file(saved_path()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("{}: {e}", saved_path().display())),
        }
        if list(nft::TABLE)?.is_some() {
            nft(&["delete", "table", "inet", nft::TABLE], None)?;
        }
        Ok(())
    }

    /// Ok(false) only when it was possible to look and nothing is there.
    pub fn installed() -> Result<bool, String> {
        Ok(list(nft::TABLE)?.is_some() || (saved_path().is_file() && boot_enabled()))
    }

    /// The temporary allow-all from an earlier run that ended without
    /// cleaning up: removed (called at start and by systemd after a stop).
    pub fn reset_open() -> Result<(), String> {
        if list(nft::TABLE)?.is_some() {
            nft(&["flush", "chain", "inet", nft::TABLE, "open"], None)?;
        }
        super::OWN_ALLOW_ALL.lock().unwrap().clear();
        Ok(())
    }

    /// Plain DNS from programs to the guard's proxy (see nft::dns_capture_script).
    pub fn dns_capture(on: bool) -> Result<(), String> {
        if on {
            let gid = crate::pia::engine_gid();
            nft(&["-f", "-"], Some(&nft::dns_capture_script(gid)))?;
            return match dns_capture_active()? {
                true => Ok(()),
                false => Err("the DNS redirect rules did not appear in nftables".into()),
            };
        }
        if list(nft::DNS_TABLE)?.is_some() {
            nft(&["delete", "table", "inet", nft::DNS_TABLE], None)?;
        }
        Ok(())
    }

    pub fn dns_capture_active() -> Result<bool, String> {
        Ok(list(nft::DNS_TABLE)?.is_some_and(|t| t.contains(nft::DNS_MARKER) && t.contains("redirect to :53")))
    }

    pub fn verify(expected: &[FilterSpec]) -> Result<(), String> {
        if expected.first().map(|f| f.kind) == Some(Kind::BootTime) {
            if !saved_path().is_file() {
                return Err("the saved ruleset for boot is missing".into());
            }
            if !boot_enabled() {
                return Err(format!("{BOOT_UNIT} is not enabled - the rules would not load before the network at the next boot"));
            }
            return Ok(());
        }
        let live = list(nft::TABLE)?.ok_or("PIA Lite's nftables table is missing")?;
        let header = live.lines().find(|l| l.trim_start().starts_with("type filter hook output")).unwrap_or("");
        if !(header.contains("hook output")
            && header.contains("policy accept")
            && (header.contains("priority 0") || header.contains("priority filter")))
        {
            return Err(format!("the 'out' chain is not hooked as planned ({})", header.trim()));
        }
        let have: Vec<String> = nft::chain_rules(&live, "out").ok_or("chain 'out' is missing")?.into_iter().map(|(b, _)| b).collect();
        let want = canonical(expected)?;
        if have != want {
            let i = have.iter().zip(&want).position(|(a, b)| a != b).unwrap_or(have.len().min(want.len()));
            return Err(format!(
                "nftables rule {} differs: have '{}', want '{}' ({} rules, {} planned)",
                i,
                have.get(i).map(String::as_str).unwrap_or("-"),
                want.get(i).map(String::as_str).unwrap_or("-"),
                have.len(),
                want.len()
            ));
        }
        check_open(&live)
    }

    /// An allow-all being added right now (its handle isn't known yet).
    static OPENING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

    /// Chain "open" may hold only the guard's own allow-all (review V63-05).
    fn check_open(live: &str) -> Result<(), String> {
        let owned = super::OWN_ALLOW_ALL.lock().unwrap().clone();
        let opening = OPENING.load(std::sync::atomic::Ordering::SeqCst);
        for (rule, handle) in nft::chain_rules(live, "open").ok_or("chain 'open' is missing")? {
            let ours = owned.contains(&handle) || opening;
            if !(ours && rule == "accept comment \"pialite:allow\"") {
                return Err(format!("chain 'open' has a rule the guard didn't add: '{rule}' (handle {handle})"));
            }
        }
        Ok(())
    }

    pub fn block_floor(known: &[FilterSpec]) -> Result<(), String> {
        let live = list(nft::TABLE)?.ok_or("PIA Lite's nftables table is missing")?;
        let have = nft::chain_rules(&live, "out").ok_or("chain 'out' is missing")?;
        let mut ok_shapes: Vec<String> = canonical(known)?.iter().map(|r| strip_comment(r).to_string()).collect();
        ok_shapes.extend(canonical(&[])?.iter().map(|r| r.to_string())); // the preamble alone
        for v6 in [false, true] {
            let floor = FilterSpec { index: 0, kind: Kind::Persistent, v6, permit: false, weight: 0, cond: super::Cond::All };
            let want = canonical(std::slice::from_ref(&floor))?;
            let floor_rule = want.iter().map(|r| strip_comment(r)).find(|r| r.contains("reject")).unwrap_or("").to_string();
            if !have.iter().any(|(r, _)| strip_comment(r) == floor_rule) {
                return Err(format!("no block-everything rule for {}", if v6 { "IPv6" } else { "IPv4" }));
            }
        }
        if let Some((r, _)) = have.iter().find(|(r, _)| !ok_shapes.iter().any(|k| k == strip_comment(r) || k == r)) {
            return Err(format!("an unrecognised rule in PIA Lite's table: '{r}'"));
        }
        check_open(&live)
    }

    pub fn startup_report(plan: &[Rule]) -> String {
        let table = match list(nft::TABLE) {
            Err(e) => return format!("found at start: nftables could not be read ({e})"),
            Ok(None) => "no PIA Lite table".to_string(),
            Ok(Some(_)) => match verify(&specs(plan, Kind::Persistent)) {
                Ok(()) => "PIA Lite table present (matching the plan)".to_string(),
                Err(e) => format!("PIA Lite table present, but {e}"),
            },
        };
        format!(
            "found at start, before any change: {table}; saved boot ruleset {}; {BOOT_UNIT} {}",
            if saved_path().is_file() { "present" } else { "absent" },
            if boot_enabled() { "enabled" } else { "not enabled" }
        )
    }

    pub fn describe() -> Result<Vec<String>, String> {
        let mut out = vec![];
        if let Some(live) = list(nft::TABLE)? {
            for (r, h) in nft::chain_rules(&live, "out").unwrap_or_default() {
                let c = nft::comment_of(&r).to_string();
                match c.strip_prefix("pialite:p:") {
                    Some(n) => out.push(format!("persistent #{n:<2} {}  [handle {h}]", strip_comment(&r))),
                    None if c == "pialite:ndp" || c == "pialite:open" => {
                        out.push(format!("linux-only     {}  [handle {h}]", strip_comment(&r)))
                    }
                    None => out.push(format!("other          {r}  [handle {h}]")),
                }
            }
            for (r, h) in nft::chain_rules(&live, "open").unwrap_or_default() {
                out.push(format!("temporary allow-all {r}  [handle {h}]"));
            }
        }
        out.push(format!(
            "boot-time  #0  saved ruleset loaded before the network starts: {}, {BOOT_UNIT} {}",
            if saved_path().is_file() { "present" } else { "absent" },
            if boot_enabled() { "enabled" } else { "not enabled" }
        ));
        super::sort_rule_lines(&mut out);
        Ok(out)
    }

    pub fn diagnose() -> String {
        let version = nft(&["--version"], None).unwrap_or_else(|e| e).trim().to_string();
        match list(nft::TABLE) {
            Ok(Some(t)) => format!(
                "{version}; table inet {}: {} rules in 'out', {} in 'open'",
                nft::TABLE,
                nft::chain_rules(&t, "out").map(|r| r.len()).unwrap_or(0),
                nft::chain_rules(&t, "open").map(|r| r.len()).unwrap_or(0)
            ),
            Ok(None) => format!("{version}; no PIA Lite table"),
            Err(e) => format!("{version}; {e}"),
        }
    }

    /// The guard's temporary allow-all (rule handle kept until dropped).
    pub struct OpenAll(u64);
    impl Drop for OpenAll {
        fn drop(&mut self) {
            let h = self.0.to_string();
            let _ = nft(&["delete", "rule", "inet", nft::TABLE, "open", "handle", &h], None); // gone first...
            super::OWN_ALLOW_ALL.lock().unwrap().retain(|i| *i != self.0); // ...then forgotten
        }
    }

    pub fn open_all() -> Result<OpenAll, String> {
        // while nftables adds it (handle not known yet) a check accepts it (V64-05)
        OPENING.store(true, std::sync::atomic::Ordering::SeqCst);
        let echo = nft(&["--echo", "--handle", "add", "rule", "inet", nft::TABLE, "open", "accept", "comment", "\"pialite:allow\""], None);
        let echo = echo.inspect_err(|_| OPENING.store(false, std::sync::atomic::Ordering::SeqCst))?;
        let handle = echo
            .lines()
            .find_map(|l| l.rsplit_once("# handle ").and_then(|(_, h)| h.trim().parse::<u64>().ok()))
            .ok_or_else(|| format!("nftables didn't say which rule it added ({})", echo.trim()))?;
        super::OWN_ALLOW_ALL.lock().unwrap().push(handle);
        OPENING.store(false, std::sync::atomic::Ordering::SeqCst);
        Ok(OpenAll(handle))
    }
}

#[cfg(all(windows, not(test)))]
mod win {
    use super::{specs, Cond, FilterSpec, Kind, Rule, MAX_FILTERS};
    use std::ffi::c_void;
    use std::ptr::{null, null_mut};
    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::{
        FWP_E_FILTER_NOT_FOUND, FWP_E_IN_USE, FWP_E_PROVIDER_NOT_FOUND, FWP_E_SUBLAYER_NOT_FOUND, HANDLE,
    };
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::*;

    // Fixed IDs so we can always find (and remove) exactly our own rules.
    const PROVIDER: GUID = GUID::from_u128(0x5a1f7e2c_3b4d_4c8a_9e61_2f0b6d1c7a01);
    const SUBLAYER: GUID = GUID::from_u128(0x5a1f7e2c_3b4d_4c8a_9e61_2f0b6d1c7a02);
    const FILTER_BASE: u128 = 0x5a1f7e2c_3b4d_4c8a_9e61_2f0b6d1d0000;
    const BOOT_BASE: u128 = FILTER_BASE + 0x100; // persistent keys use +0x00..+0x7F
    const SUBLAYER_WEIGHT: u16 = 0x7000;

    fn key(kind: Kind, i: u32) -> GUID {
        GUID::from_u128(
            match kind {
                Kind::Persistent => FILTER_BASE,
                Kind::BootTime => BOOT_BASE,
            } + i as u128,
        )
    }

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    fn check(what: &str, rc: u32) -> Result<(), String> {
        if rc == 0 {
            Ok(())
        } else {
            Err(format!("{what} failed (error 0x{rc:08X})"))
        }
    }

    fn same_guid(a: &GUID, b: &GUID) -> bool {
        a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
    }

    struct Engine(HANDLE);
    // A WFP engine handle isn't tied to the thread that opened it.
    unsafe impl Send for Engine {}
    impl Engine {
        fn open(dynamic: bool) -> Result<Engine, String> {
            let name = wide("PIA Lite guard");
            let mut session = FWPM_SESSION0::default();
            session.displayData.name = name.as_ptr() as *mut u16;
            if dynamic {
                session.flags = FWPM_SESSION_FLAG_DYNAMIC;
            }
            session.txnWaitTimeoutInMSec = 10_000;
            let mut h: HANDLE = null_mut();
            // RPC_C_AUTHN_WINNT = 10
            let rc = unsafe { FwpmEngineOpen0(null(), 10, null(), &session, &mut h) };
            check("Opening the Windows firewall engine", rc)?;
            Ok(Engine(h))
        }
        fn txn<T>(&self, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
            self.txn_as("Saving firewall rules", f)
        }
        /// `what` names the step in an error (Windows only reports most
        /// problems when the whole change is saved).
        fn txn_as<T>(&self, what: &str, f: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
            check("Starting firewall transaction", unsafe { FwpmTransactionBegin0(self.0, 0) })?;
            match f() {
                Ok(v) => {
                    check(what, unsafe { FwpmTransactionCommit0(self.0) })?;
                    Ok(v)
                }
                Err(e) => {
                    unsafe { FwpmTransactionAbort0(self.0) };
                    Err(e)
                }
            }
        }
    }
    impl Drop for Engine {
        fn drop(&mut self) {
            unsafe { FwpmEngineClose0(self.0) };
        }
    }

    /// App ID blob from Windows (freed when dropped).
    struct AppId(*mut FWP_BYTE_BLOB);
    impl Drop for AppId {
        fn drop(&mut self) {
            unsafe { FwpmFreeMemory0(&mut self.0 as *mut _ as *mut *mut c_void) };
        }
    }

    /// A filter read back from Windows (freed when dropped).
    struct Got(*mut FWPM_FILTER0);
    impl Drop for Got {
        fn drop(&mut self) {
            unsafe { FwpmFreeMemory0(&mut self.0 as *mut _ as *mut *mut c_void) };
        }
    }
    fn get(e: &Engine, k: &GUID) -> Option<Got> {
        let mut f: *mut FWPM_FILTER0 = null_mut();
        (unsafe { FwpmFilterGetByKey0(e.0, k, &mut f) } == 0 && !f.is_null()).then_some(Got(f))
    }
    /// Like `get`, but "not there" and "couldn't ask" are different answers.
    fn lookup(e: &Engine, k: &GUID) -> Result<bool, String> {
        let mut f: *mut FWPM_FILTER0 = null_mut();
        let rc = unsafe { FwpmFilterGetByKey0(e.0, k, &mut f) };
        if rc == 0 && !f.is_null() {
            drop(Got(f));
            Ok(true)
        } else if rc == FWP_E_FILTER_NOT_FOUND as u32 {
            Ok(false)
        } else {
            Err(format!("could not read firewall rule (error 0x{rc:08X})"))
        }
    }
    fn guid_u128(g: &GUID) -> u128 {
        ((g.data1 as u128) << 96) | ((g.data2 as u128) << 80) | ((g.data3 as u128) << 64) | u64::from_be_bytes(g.data4) as u128
    }
    /// Is this key in one of our fixed key ranges? (kind, index)
    fn our_key(g: &GUID) -> Option<(Kind, u32)> {
        let v = guid_u128(g);
        if (FILTER_BASE..FILTER_BASE + MAX_FILTERS as u128).contains(&v) {
            Some((Kind::Persistent, (v - FILTER_BASE) as u32))
        } else if (BOOT_BASE..BOOT_BASE + MAX_FILTERS as u128).contains(&v) {
            Some((Kind::BootTime, (v - BOOT_BASE) as u32))
        } else {
            None
        }
    }

    /// Conditions plus all the memory they point at (kept alive until added).
    /// The address masks are boxed ON PURPOSE: conditions hold raw pointers to
    /// them, and a Box keeps each one at a fixed address when the Vec grows.
    /// (clippy's vec_box advice would turn those into dangling pointers.)
    #[derive(Default)]
    #[allow(clippy::vec_box)]
    struct Conds {
        list: Vec<FWPM_FILTER_CONDITION0>,
        v4: Vec<Box<FWP_V4_ADDR_AND_MASK>>,
        v6: Vec<Box<FWP_V6_ADDR_AND_MASK>>,
        apps: Vec<AppId>,
    }
    impl Conds {
        fn push(&mut self, field: GUID, match_type: FWP_MATCH_TYPE, value: FWP_CONDITION_VALUE0) {
            self.list.push(FWPM_FILTER_CONDITION0 { fieldKey: field, matchType: match_type, conditionValue: value });
        }
        fn u16(&mut self, field: GUID, v: u16) {
            self.push(field, FWP_MATCH_EQUAL, FWP_CONDITION_VALUE0 { r#type: FWP_UINT16, Anonymous: FWP_CONDITION_VALUE0_0 { uint16: v } });
        }
    }

    /// The WFP conditions for one rule on one layer: never two alternatives
    /// of the same field in one filter.
    fn build(cond: &Cond, v6: bool) -> Result<Conds, String> {
        let mut c = Conds::default();
        match cond {
            Cond::All => {}
            Cond::Loopback => c.push(
                FWPM_CONDITION_FLAGS,
                FWP_MATCH_FLAGS_ALL_SET,
                FWP_CONDITION_VALUE0 { r#type: FWP_UINT32, Anonymous: FWP_CONDITION_VALUE0_0 { uint32: FWP_CONDITION_FLAG_IS_LOOPBACK } },
            ),
            Cond::Dhcp => {
                c.push(
                    FWPM_CONDITION_IP_PROTOCOL,
                    FWP_MATCH_EQUAL,
                    FWP_CONDITION_VALUE0 { r#type: FWP_UINT8, Anonymous: FWP_CONDITION_VALUE0_0 { uint8: 17 } },
                );
                c.u16(FWPM_CONDITION_IP_LOCAL_PORT, if v6 { 546 } else { 68 });
                c.u16(FWPM_CONDITION_IP_REMOTE_PORT, if v6 { 547 } else { 67 });
            }
            Cond::RemotePort(p) => c.u16(FWPM_CONDITION_IP_REMOTE_PORT, *p),
            Cond::Subnet4(addr, prefix) => {
                let b = Box::new(FWP_V4_ADDR_AND_MASK { addr: u32::from_be_bytes(*addr), mask: super::v4_mask(*prefix) });
                let p = &*b as *const _ as *mut FWP_V4_ADDR_AND_MASK;
                c.v4.push(b);
                c.push(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    FWP_MATCH_EQUAL,
                    FWP_CONDITION_VALUE0 { r#type: FWP_V4_ADDR_MASK, Anonymous: FWP_CONDITION_VALUE0_0 { v4AddrMask: p } },
                );
            }
            Cond::Subnet6(first, prefix) => {
                let mut addr = [0u8; 16];
                addr[..2].copy_from_slice(&first.to_be_bytes());
                let b = Box::new(FWP_V6_ADDR_AND_MASK { addr, prefixLength: *prefix });
                let p = &*b as *const _ as *mut FWP_V6_ADDR_AND_MASK;
                c.v6.push(b);
                c.push(
                    FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    FWP_MATCH_EQUAL,
                    FWP_CONDITION_VALUE0 { r#type: FWP_V6_ADDR_MASK, Anonymous: FWP_CONDITION_VALUE0_0 { v6AddrMask: p } },
                );
            }
            Cond::Group(_) | Cond::Mark(_) => return Err("a Linux-only rule in the Windows plan".into()),
            Cond::App(path) => {
                let w = wide(path);
                let mut blob: *mut FWP_BYTE_BLOB = null_mut();
                if unsafe { FwpmGetAppIdFromFileName0(w.as_ptr(), &mut blob) } != 0 || blob.is_null() {
                    // say which one - PIA can't connect without its programs (review N-01)
                    return Err(format!("could not identify PIA program {path}"));
                }
                c.apps.push(AppId(blob));
                c.push(
                    FWPM_CONDITION_ALE_APP_ID,
                    FWP_MATCH_EQUAL,
                    FWP_CONDITION_VALUE0 { r#type: FWP_BYTE_BLOB_TYPE, Anonymous: FWP_CONDITION_VALUE0_0 { byteBlob: blob } },
                );
            }
        }
        Ok(c)
    }

    fn layer(v6: bool) -> GUID {
        if v6 {
            FWPM_LAYER_ALE_AUTH_CONNECT_V6
        } else {
            FWPM_LAYER_ALE_AUTH_CONNECT_V4
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn add_filter(
        e: &Engine,
        key: Option<GUID>,
        layer: GUID,
        weight: u8,
        permit: bool,
        conds: &mut Conds,
        kind: Option<Kind>,
        name: &str,
    ) -> Result<u64, String> {
        let wname = wide(&format!("PIA Lite: {name}"));
        let mut f = FWPM_FILTER0::default();
        if let Some(k) = key {
            f.filterKey = k;
        }
        f.displayData.name = wname.as_ptr() as *mut u16;
        f.layerKey = layer;
        match kind {
            Some(Kind::BootTime) => {
                // built-in objects only: no provider, default (universal) sublayer
                f.flags = FWPM_FILTER_FLAG_BOOTTIME;
            }
            Some(Kind::Persistent) | None => {
                f.flags = if kind.is_some() { FWPM_FILTER_FLAG_PERSISTENT } else { 0 }; // None = dynamic
                f.providerKey = &PROVIDER as *const GUID as *mut GUID;
                f.subLayerKey = SUBLAYER;
            }
        }
        f.weight = FWP_VALUE0 { r#type: FWP_UINT8, Anonymous: FWP_VALUE0_0 { uint8: weight } };
        f.numFilterConditions = conds.list.len() as u32;
        f.filterCondition = if conds.list.is_empty() { null_mut() } else { conds.list.as_mut_ptr() };
        f.action.r#type = if permit { FWP_ACTION_PERMIT } else { FWP_ACTION_BLOCK };
        let mut id = 0u64;
        check(&format!("Adding rule '{name}'"), unsafe { FwpmFilterAdd0(e.0, &f, null_mut(), &mut id) })?;
        Ok(id)
    }

    // Inside a transaction we never make calls that are *expected* to fail
    // (like deleting something that isn't there): look first, then act -
    // the same pattern WireGuard's Windows firewall code uses.
    fn filter_exists(e: &Engine, k: &GUID) -> bool {
        get(e, k).is_some()
    }
    fn provider_exists(e: &Engine) -> bool {
        let mut p: *mut FWPM_PROVIDER0 = null_mut();
        let found = unsafe { FwpmProviderGetByKey0(e.0, &PROVIDER, &mut p) } == 0;
        if found {
            unsafe { FwpmFreeMemory0(&mut p as *mut _ as *mut *mut c_void) };
        }
        found
    }
    fn sublayer_exists(e: &Engine) -> bool {
        let mut s: *mut FWPM_SUBLAYER0 = null_mut();
        let found = unsafe { FwpmSubLayerGetByKey0(e.0, &SUBLAYER, &mut s) } == 0;
        if found {
            unsafe { FwpmFreeMemory0(&mut s as *mut _ as *mut *mut c_void) };
        }
        found
    }

    /// Our provider object as Windows holds it: Err(why) if changed/missing.
    fn check_provider(e: &Engine) -> Result<(), String> {
        let mut p: *mut FWPM_PROVIDER0 = null_mut();
        if unsafe { FwpmProviderGetByKey0(e.0, &PROVIDER, &mut p) } != 0 || p.is_null() {
            return Err("PIA Lite's firewall provider is missing".into());
        }
        let flags = unsafe { (*p).flags };
        unsafe { FwpmFreeMemory0(&mut p as *mut _ as *mut *mut c_void) };
        if flags & FWPM_PROVIDER_FLAG_PERSISTENT == 0 || flags & FWPM_PROVIDER_FLAG_DISABLED != 0 {
            return Err(format!("PIA Lite's firewall provider changed (flags 0x{flags:x})"));
        }
        Ok(())
    }

    /// Our sublayer object: weight (its priority against other firewalls),
    /// persistence and owner must be as we made it (review V4-07).
    fn check_sublayer(e: &Engine) -> Result<(), String> {
        let mut s: *mut FWPM_SUBLAYER0 = null_mut();
        if unsafe { FwpmSubLayerGetByKey0(e.0, &SUBLAYER, &mut s) } != 0 || s.is_null() {
            return Err("PIA Lite's firewall sublayer is missing".into());
        }
        let (weight, flags, owner_ok) = unsafe {
            let x = &*s;
            (x.weight, x.flags, !x.providerKey.is_null() && same_guid(&*x.providerKey, &PROVIDER))
        };
        unsafe { FwpmFreeMemory0(&mut s as *mut _ as *mut *mut c_void) };
        if weight != SUBLAYER_WEIGHT || flags & FWPM_SUBLAYER_FLAG_PERSISTENT == 0 || !owner_ok {
            return Err(format!("PIA Lite's firewall sublayer changed (weight 0x{weight:x}, flags 0x{flags:x}, owner ok: {owner_ok})"));
        }
        Ok(())
    }

    /// Are provider and sublayer as planned? (None = yes, or not there yet)
    fn objects_changed(e: &Engine) -> Option<String> {
        if sublayer_exists(e) {
            if let Err(x) = check_sublayer(e) {
                return Some(x);
            }
        }
        if provider_exists(e) {
            if let Err(x) = check_provider(e) {
                return Some(x);
            }
        }
        None
    }

    /// Add provider and sublayer if they are missing. Never deletes anything:
    /// replacing changed ones is a separate, rarer step (replace_objects), so
    /// a normal rule refresh can't fail on them (v0.6.0 lock-out).
    fn add_missing_objects(e: &Engine) -> Result<(), String> {
        let pname = wide("PIA Lite");
        let p = FWPM_PROVIDER0 {
            providerKey: PROVIDER,
            displayData: FWPM_DISPLAY_DATA0 { name: pname.as_ptr() as *mut u16, description: null_mut() },
            flags: FWPM_PROVIDER_FLAG_PERSISTENT,
            ..Default::default()
        };
        if !provider_exists(e) {
            check("Adding firewall provider", unsafe { FwpmProviderAdd0(e.0, &p, null_mut()) })?;
        }
        let sname = wide("PIA Lite internet block");
        let s = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER,
            displayData: FWPM_DISPLAY_DATA0 { name: sname.as_ptr() as *mut u16, description: null_mut() },
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
            providerKey: &PROVIDER as *const GUID as *mut GUID,
            weight: SUBLAYER_WEIGHT,
            ..Default::default()
        };
        if !sublayer_exists(e) {
            check("Adding firewall sublayer", unsafe { FwpmSubLayerAdd0(e.0, &s, null_mut()) })?;
        }
        Ok(())
    }

    /// A changed provider/sublayer: delete both and add them again (inside
    /// the caller's transaction, after our filters were removed). Fails while
    /// anything else still uses them - e.g. the temporary allow-all, or a
    /// session left behind by another process (see diagnose()).
    fn replace_objects(e: &Engine) -> Result<(), String> {
        if sublayer_exists(e) {
            check("Deleting the changed firewall sublayer", unsafe { FwpmSubLayerDeleteByKey0(e.0, &SUBLAYER) })?;
        }
        if provider_exists(e) {
            check("Deleting the changed firewall provider", unsafe { FwpmProviderDeleteByKey0(e.0, &PROVIDER) })?;
        }
        add_missing_objects(e)
    }

    fn delete_persistent(e: &Engine) -> Result<(), String> {
        for i in 0..MAX_FILTERS {
            let k = key(Kind::Persistent, i);
            if filter_exists(e, &k) {
                check("Removing old rule", unsafe { FwpmFilterDeleteByKey0(e.0, &k) })?;
            }
        }
        Ok(())
    }

    /// Replace our persistent rules with `rules` in one all-or-nothing step.
    /// Returns the filters that now exist (for later verification).
    pub fn install(rules: &[Rule]) -> Result<Vec<FilterSpec>, String> {
        let e = Engine::open(false)?;
        let want = specs(rules, Kind::Persistent);
        if want.len() as u32 > MAX_FILTERS {
            return Err("too many rules".into());
        }
        // a changed provider/sublayer is replaced only when it is changed, and
        // the error says so (v0.6.0: an "in use" here locked a user out)
        let changed = objects_changed(&e);
        let what = match &changed {
            Some(why) => format!("Saving firewall rules with a new provider/sublayer ({why})"),
            None => format!("Saving firewall rules (replacing {} rules)", want.len()),
        };
        e.txn_as(&what, || {
            delete_persistent(&e)?;
            if changed.is_some() {
                replace_objects(&e)?;
            } else {
                add_missing_objects(&e)?;
            }
            let mut n = 0u32;
            for v6 in [false, true] {
                for r in rules.iter().filter(|r| r.cond.applies(v6)) {
                    let mut conds = build(&r.cond, v6)?;
                    add_filter(
                        &e,
                        Some(key(Kind::Persistent, n)),
                        layer(v6),
                        r.weight,
                        r.permit,
                        &mut conds,
                        Some(Kind::Persistent),
                        &r.name,
                    )?;
                    n += 1;
                }
            }
            Ok(())
        })?;
        verify(&want)?;
        Ok(want)
    }

    /// Boot-time rules, in their own step. Old ones are removed first outside
    /// a transaction (errors ignored). Read back and checked afterwards (N-08).
    pub fn install_boot(rules: &[Rule]) -> Result<Vec<FilterSpec>, String> {
        let e = Engine::open(false)?;
        for i in 0..MAX_FILTERS {
            unsafe { FwpmFilterDeleteByKey0(e.0, &key(Kind::BootTime, i)) };
        }
        let want = specs(rules, Kind::BootTime);
        e.txn(|| {
            let mut n = 0u32;
            for v6 in [false, true] {
                for r in rules.iter().filter(|r| r.cond.applies(v6)) {
                    let mut conds = build(&r.cond, v6)?;
                    add_filter(&e, Some(key(Kind::BootTime, n)), layer(v6), r.weight, r.permit, &mut conds, Some(Kind::BootTime), &r.name)?;
                    n += 1;
                }
            }
            Ok(())
        })?;
        verify(&want)?;
        Ok(want)
    }

    pub fn remove_boot() -> Result<(), String> {
        let e = Engine::open(false)?;
        for i in 0..MAX_FILTERS {
            unsafe { FwpmFilterDeleteByKey0(e.0, &key(Kind::BootTime, i)) };
        }
        if (0..MAX_FILTERS).any(|i| filter_exists(&e, &key(Kind::BootTime, i))) {
            return Err("boot-time rules could not be removed".into());
        }
        Ok(())
    }

    /// Same condition value? Compares the data itself, not just pointers.
    fn value_eq(a: &FWP_CONDITION_VALUE0, b: &FWP_CONDITION_VALUE0) -> bool {
        if a.r#type != b.r#type {
            return false;
        }
        unsafe {
            match a.r#type {
                FWP_UINT8 => a.Anonymous.uint8 == b.Anonymous.uint8,
                FWP_UINT16 => a.Anonymous.uint16 == b.Anonymous.uint16,
                FWP_UINT32 => a.Anonymous.uint32 == b.Anonymous.uint32,
                FWP_V4_ADDR_MASK => {
                    let (x, y) = (a.Anonymous.v4AddrMask, b.Anonymous.v4AddrMask);
                    !x.is_null() && !y.is_null() && (*x).addr == (*y).addr && (*x).mask == (*y).mask
                }
                FWP_V6_ADDR_MASK => {
                    let (x, y) = (a.Anonymous.v6AddrMask, b.Anonymous.v6AddrMask);
                    !x.is_null() && !y.is_null() && (*x).addr == (*y).addr && (*x).prefixLength == (*y).prefixLength
                }
                FWP_BYTE_BLOB_TYPE => {
                    let (x, y) = (a.Anonymous.byteBlob, b.Anonymous.byteBlob);
                    !x.is_null()
                        && !y.is_null()
                        && (*x).size == (*y).size
                        && ((*x).size == 0
                            || std::slice::from_raw_parts((*x).data, (*x).size as usize)
                                == std::slice::from_raw_parts((*y).data, (*y).size as usize))
                }
                _ => false, // a type we never use: a difference
            }
        }
    }

    /// We add the weight as a UINT8 range index. If Windows hands back another
    /// type, the computed weight's top 4 bits must be that index; anything else
    /// is a difference (no silent pass on an unexpected type).
    fn weight_is(f: &FWPM_FILTER0, weight: u8) -> bool {
        unsafe {
            if f.weight.r#type == FWP_UINT8 {
                f.weight.Anonymous.uint8 == weight
            } else {
                f.effectiveWeight.r#type == FWP_UINT64
                    && !f.effectiveWeight.Anonymous.uint64.is_null()
                    && (*f.effectiveWeight.Anonymous.uint64 >> 60) as u8 == weight
            }
        }
    }

    /// The filter's conditions are exactly those `cond` is built from (any
    /// order). Ok(Some(what differs)), Ok(None) = the same.
    fn conditions_are(f: &FWPM_FILTER0, cond: &Cond, v6: bool) -> Result<Option<&'static str>, String> {
        let want = build(cond, v6)?;
        let have: &[FWPM_FILTER_CONDITION0] = if f.numFilterConditions == 0 || f.filterCondition.is_null() {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(f.filterCondition, f.numFilterConditions as usize) }
        };
        if have.len() != want.list.len() {
            return Ok(Some("number of conditions"));
        }
        // order-independent: every planned condition matches one stored one
        let mut used = vec![false; have.len()];
        let all = want.list.iter().all(|w| {
            let hit = have.iter().enumerate().position(|(i, h)| {
                !used[i]
                    && same_guid(&h.fieldKey, &w.fieldKey)
                    && h.matchType == w.matchType
                    && value_eq(&h.conditionValue, &w.conditionValue)
            });
            if let Some(i) = hit {
                used[i] = true;
            }
            hit.is_some()
        });
        Ok((!all).then_some("condition values"))
    }

    /// Compare one stored filter with what it must be - every property we set,
    /// including each condition's value (review V3-05).
    fn check_filter(f: &FWPM_FILTER0, s: &FilterSpec) -> Result<(), String> {
        let mut bad = vec![];
        if !same_guid(&f.layerKey, &layer(s.v6)) {
            bad.push("layer");
        }
        let want_action = if s.permit { FWP_ACTION_PERMIT } else { FWP_ACTION_BLOCK };
        if f.action.r#type != want_action {
            bad.push("action");
        }
        let want_flag = match s.kind {
            Kind::Persistent => FWPM_FILTER_FLAG_PERSISTENT,
            Kind::BootTime => FWPM_FILTER_FLAG_BOOTTIME,
        };
        // must have its kind's flag; must NOT have flags that weaken or
        // switch it off (anything else Windows adds on its own is allowed)
        const RISKY: u32 =
            FWPM_FILTER_FLAG_DISABLED | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT | FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
        if f.flags & want_flag == 0 || f.flags & RISKY != 0 {
            bad.push("flags");
        }
        if !weight_is(f, s.weight) {
            bad.push("weight");
        }
        match s.kind {
            Kind::Persistent => {
                if f.providerKey.is_null() || !same_guid(unsafe { &*f.providerKey }, &PROVIDER) {
                    bad.push("provider");
                }
                if !same_guid(&f.subLayerKey, &SUBLAYER) {
                    bad.push("sublayer");
                }
            }
            Kind::BootTime => {
                if !f.providerKey.is_null() {
                    bad.push("provider");
                }
                if !same_guid(&f.subLayerKey, &FWPM_SUBLAYER_UNIVERSAL) && guid_u128(&f.subLayerKey) != 0 {
                    bad.push("sublayer");
                }
            }
        }
        // the conditions it must have, built exactly as when it was added
        match conditions_are(f, &s.cond, s.v6) {
            Err(e) => return Err(format!("rule #{}: {e}", s.index)),
            Ok(Some(why)) => bad.push(why),
            Ok(None) => {}
        }
        if bad.is_empty() {
            Ok(())
        } else {
            Err(format!("rule #{} changed ({})", s.index, bad.join(", ")))
        }
    }

    fn check_one(e: &Engine, s: &FilterSpec) -> Result<(), String> {
        let Some(g) = get(e, &key(s.kind, s.index)) else { return Err(format!("rule #{} missing", s.index)) };
        check_filter(unsafe { &*g.0 }, s)
    }

    /// Every filter on one layer (optionally only one provider's), handed to `each`.
    fn list(e: &Engine, v6: bool, provider: Option<&GUID>, flags: u32, mut each: impl FnMut(&FWPM_FILTER0)) -> Result<(), String> {
        let tpl = FWPM_FILTER_ENUM_TEMPLATE0 {
            providerKey: provider.map_or(null_mut(), |p| p as *const GUID as *mut GUID),
            layerKey: layer(v6),
            enumType: FWP_FILTER_ENUM_OVERLAPPING,
            flags,
            actionMask: 0xFFFF_FFFF,
            ..Default::default()
        };
        let mut h: HANDLE = null_mut();
        check("Listing firewall rules", unsafe { FwpmFilterCreateEnumHandle0(e.0, &tpl, &mut h) })?;
        let rc = loop {
            let mut entries: *mut *mut FWPM_FILTER0 = null_mut();
            let mut n = 0u32;
            let rc = unsafe { FwpmFilterEnum0(e.0, h, 512, &mut entries, &mut n) };
            if rc != 0 || entries.is_null() {
                break rc;
            }
            for i in 0..n as usize {
                each(unsafe { &**entries.add(i) });
            }
            unsafe { FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut c_void) };
            if n < 512 {
                break 0;
            }
        };
        unsafe { FwpmFilterDestroyEnumHandle0(e.0, h) };
        check("Listing firewall rules", rc)
    }

    /// Persistent filters under our provider that aren't in the plan.
    fn unexpected(e: &Engine, expected: &[FilterSpec]) -> Result<usize, String> {
        let mut extra = 0;
        for v6 in [false, true] {
            list(e, v6, Some(&PROVIDER), 0, |f| {
                // our own temporary allow-all (dynamic) is fine
                if f.flags & FWPM_FILTER_FLAG_PERSISTENT != 0 && !expected.iter().any(|s| same_guid(&f.filterKey, &key(s.kind, s.index))) {
                    extra += 1;
                }
            })?;
        }
        Ok(extra)
    }

    /// Boot-time filters may only show up when listed with the boot-time flag
    /// (Windows stops enforcing them once its firewall engine runs, but keeps
    /// them for the next start). Check them that way, extras included.
    fn verify_boot_listed(e: &Engine, expected: &[FilterSpec]) -> Result<(), String> {
        let mut found = vec![false; expected.len()];
        let mut first_bad = None;
        let mut extra = 0;
        for v6 in [false, true] {
            list(e, v6, None, FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY, |f| {
                match expected.iter().position(|s| same_guid(&f.filterKey, &key(s.kind, s.index))) {
                    Some(i) => {
                        found[i] = true;
                        if let Err(why) = check_filter(f, &expected[i]) {
                            first_bad.get_or_insert(why);
                        }
                    }
                    None if matches!(our_key(&f.filterKey), Some((Kind::BootTime, _))) => extra += 1,
                    None => {}
                }
            })?;
        }
        if let Some(why) = first_bad {
            return Err(why);
        }
        if extra > 0 {
            return Err(format!("{extra} unexpected boot-time rule(s) with PIA Lite's IDs"));
        }
        match found.iter().position(|f| !f) {
            Some(i) => Err(format!("boot-time rule #{i} missing")),
            None => Ok(()),
        }
    }

    /// Are exactly the expected filters in Windows, as planned?
    pub fn verify(expected: &[FilterSpec]) -> Result<(), String> {
        let e = Engine::open(false)?;
        let Some(first) = expected.first() else { return Ok(()) };
        if first.kind == Kind::BootTime && !lookup(&e, &key(Kind::BootTime, 0))? {
            return verify_boot_listed(&e, expected);
        }
        for s in expected {
            check_one(&e, s)?;
        }
        // every other key in our range must be empty, not just the next one
        for i in expected.len() as u32..MAX_FILTERS {
            if lookup(&e, &key(first.kind, i))? {
                return Err(format!("an extra rule #{i} has a PIA Lite ID"));
            }
        }
        if first.kind == Kind::Persistent {
            let extra = unexpected(&e, expected)?;
            if extra > 0 {
                return Err(format!("{extra} unexpected rule(s) under PIA Lite's name"));
            }
            check_provider(&e)?;
            check_sublayer(&e)?;
        }
        Ok(())
    }

    /// What the guard finds in Windows when it starts, BEFORE it changes
    /// anything (review F51-08): were the stored rules in force while the
    /// guard wasn't running yet? Provider and sublayer state, the rules
    /// against the plan, and their run-time IDs - Windows' firewall audit
    /// names the deciding rule by that ID, so the startup leak test can tell
    /// which blocks were PIA Lite's.
    pub fn startup_report(plan: &[Rule]) -> String {
        let e = match Engine::open(false) {
            Ok(e) => e,
            Err(err) => return format!("found at start: could not look ({err})"),
        };
        let provider = match check_provider(&e) {
            Ok(()) => "provider ok (persistent, enabled)".to_string(),
            Err(x) => x,
        };
        let sublayer = match check_sublayer(&e) {
            Ok(()) => "sublayer ok".to_string(),
            Err(x) => x,
        };
        let (mut ids, mut boot_ids) = (vec![], vec![]);
        for v6 in [false, true] {
            let _ = list(&e, v6, Some(&PROVIDER), 0, |f| {
                if f.flags & FWPM_FILTER_FLAG_PERSISTENT != 0 {
                    ids.push(f.filterId);
                }
            });
            let _ = list(&e, v6, None, FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY, |f| {
                if our_key(&f.filterKey).is_some() {
                    boot_ids.push(f.filterId);
                }
            });
        }
        drop(e);
        let check = if ids.is_empty() {
            "none".to_string()
        } else {
            match verify(&super::specs(plan, Kind::Persistent)) {
                Ok(()) => "matching the plan".to_string(),
                Err(x) => format!("NOT matching the plan: {x}"),
            }
        };
        let join = |v: &[u64]| v.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        format!(
            "found at start, before any change: {provider}; {sublayer}; {} persistent rules ({check}); {} boot-time rules listed; rule ids {}; boot ids {}",
            ids.len(),
            boot_ids.len(),
            join(&ids),
            join(&boot_ids)
        )
    }

    /// When a rule change fails: who else uses PIA Lite's firewall objects?
    /// Filters in our sublayer (persistent / temporary, ours or not) and the
    /// firewall sessions opened under our name, with their process ids - a
    /// session left behind by a process that didn't end keeps its temporary
    /// rules (and "in use" errors) alive.
    pub fn diagnose() -> String {
        let e = match Engine::open(false) {
            Ok(e) => e,
            Err(err) => return format!("could not look ({err})"),
        };
        let provider = check_provider(&e).err().unwrap_or_else(|| "provider ok".into());
        let sublayer = check_sublayer(&e).err().unwrap_or_else(|| "sublayer ok".into());
        let (mut persistent, mut temporary, mut foreign) = (0, 0, 0);
        for v6 in [false, true] {
            let _ = list(&e, v6, None, 0, |f| {
                if same_guid(&f.subLayerKey, &SUBLAYER) {
                    let ours = !f.providerKey.is_null() && same_guid(unsafe { &*f.providerKey }, &PROVIDER);
                    if !ours {
                        foreign += 1;
                    } else if f.flags & FWPM_FILTER_FLAG_PERSISTENT != 0 {
                        persistent += 1;
                    } else {
                        temporary += 1;
                    }
                }
            });
        }
        let me = std::process::id();
        let mut sessions = vec![];
        let mut h: HANDLE = null_mut();
        if unsafe { FwpmSessionCreateEnumHandle0(e.0, null(), &mut h) } == 0 {
            let mut entries: *mut *mut FWPM_SESSION0 = null_mut();
            let mut n = 0u32;
            if unsafe { FwpmSessionEnum0(e.0, h, 256, &mut entries, &mut n) } == 0 && !entries.is_null() {
                for i in 0..n as usize {
                    let ses = unsafe { &**entries.add(i) };
                    let name = if ses.displayData.name.is_null() {
                        String::new()
                    } else {
                        let mut len = 0;
                        while unsafe { *ses.displayData.name.add(len) } != 0 && len < 256 {
                            len += 1;
                        }
                        String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(ses.displayData.name, len) })
                    };
                    if name == "PIA Lite guard" {
                        let dynamic = if ses.flags & FWPM_SESSION_FLAG_DYNAMIC != 0 { "temporary" } else { "normal" };
                        let who = if ses.processId == me { " (this process)".to_string() } else { String::new() };
                        sessions.push(format!("pid {} {dynamic}{who}", ses.processId));
                    }
                }
                unsafe { FwpmFreeMemory0(&mut entries as *mut _ as *mut *mut c_void) };
            }
            unsafe { FwpmSessionDestroyEnumHandle0(e.0, h) };
        }
        format!(
            "{provider}; {sublayer}; in our sublayer: {persistent} stored rules, {temporary} temporary (allow-all), {foreign} not ours; our firewall sessions: {}",
            if sessions.is_empty() { "none".to_string() } else { sessions.join(", ") }
        )
    }

    /// One line per PIA Lite filter as Windows holds it: kind, family, action,
    /// weight, flags and every condition with its value - the evidence the
    /// review asked for (`pialite-guard show-rules`) - and its run-time id.
    pub fn describe() -> Result<Vec<String>, String> {
        let e = Engine::open(false)?;
        let mut out = vec![];
        let mut seen = std::collections::HashSet::new();
        for v6 in [false, true] {
            list(&e, v6, Some(&PROVIDER), 0, |f| {
                seen.insert(f.filterId);
                out.push(describe_filter(f));
            })?;
            list(&e, v6, None, FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY, |f| {
                if our_key(&f.filterKey).is_some() && seen.insert(f.filterId) {
                    out.push(describe_filter(f));
                }
            })?;
        }
        // boot-time filters readable by key but not listed
        for i in 0..MAX_FILTERS {
            if let Some(g) = get(&e, &key(Kind::BootTime, i)) {
                let f = unsafe { &*g.0 };
                if seen.insert(f.filterId) {
                    out.push(describe_filter(f));
                }
            }
        }
        super::sort_rule_lines(&mut out);
        Ok(out)
    }

    fn describe_filter(f: &FWPM_FILTER0) -> String {
        let what = match our_key(&f.filterKey) {
            Some((Kind::Persistent, i)) => format!("persistent #{i:<2}"),
            Some((Kind::BootTime, i)) => format!("boot-time  #{i:<2}"),
            None if f.flags & FWPM_FILTER_FLAG_PERSISTENT == 0 => "temporary allow-all".to_string(),
            None => "OTHER (not a PIA Lite ID)".to_string(),
        };
        let fam = if same_guid(&f.layerKey, &FWPM_LAYER_ALE_AUTH_CONNECT_V6) { "v6" } else { "v4" };
        let action = match f.action.r#type {
            FWP_ACTION_PERMIT => "PERMIT",
            FWP_ACTION_BLOCK => "BLOCK",
            _ => "OTHER",
        };
        let weight = unsafe {
            if f.weight.r#type == FWP_UINT8 {
                f.weight.Anonymous.uint8.to_string()
            } else if f.effectiveWeight.r#type == FWP_UINT64 && !f.effectiveWeight.Anonymous.uint64.is_null() {
                format!("{}*", *f.effectiveWeight.Anonymous.uint64 >> 60)
            } else {
                "?".into()
            }
        };
        let mut flags = vec![];
        if f.flags & FWPM_FILTER_FLAG_PERSISTENT != 0 {
            flags.push("PERSISTENT");
        }
        if f.flags & FWPM_FILTER_FLAG_BOOTTIME != 0 {
            flags.push("BOOTTIME");
        }
        if f.flags & FWPM_FILTER_FLAG_DISABLED != 0 {
            flags.push("DISABLED");
        }
        let conds: Vec<String> = if f.numFilterConditions == 0 || f.filterCondition.is_null() {
            vec!["(no conditions: matches everything)".into()]
        } else {
            unsafe { std::slice::from_raw_parts(f.filterCondition, f.numFilterConditions as usize) }.iter().map(describe_cond).collect()
        };
        format!("{what} {fam} {action:<6} w={weight:<3} {:<10} {}  [id {}]", flags.join("+"), conds.join(" AND "), f.filterId)
    }

    fn describe_cond(c: &FWPM_FILTER_CONDITION0) -> String {
        let k = &c.fieldKey;
        let field = if same_guid(k, &FWPM_CONDITION_ALE_APP_ID) {
            "app".to_string()
        } else if same_guid(k, &FWPM_CONDITION_IP_REMOTE_ADDRESS) {
            "remote-address".into()
        } else if same_guid(k, &FWPM_CONDITION_IP_REMOTE_PORT) {
            "remote-port".into()
        } else if same_guid(k, &FWPM_CONDITION_IP_LOCAL_PORT) {
            "local-port".into()
        } else if same_guid(k, &FWPM_CONDITION_IP_PROTOCOL) {
            "protocol".into()
        } else if same_guid(k, &FWPM_CONDITION_FLAGS) {
            "flags".into()
        } else {
            format!("field {:032x}", guid_u128(k))
        };
        let op = match c.matchType {
            FWP_MATCH_EQUAL => "=",
            FWP_MATCH_FLAGS_ALL_SET => "has all of",
            _ => "?",
        };
        let v = &c.conditionValue;
        let value = unsafe {
            match v.r#type {
                FWP_UINT8 => v.Anonymous.uint8.to_string(),
                FWP_UINT16 => v.Anonymous.uint16.to_string(),
                FWP_UINT32 => format!("0x{:x}", v.Anonymous.uint32),
                FWP_V4_ADDR_MASK if !v.Anonymous.v4AddrMask.is_null() => {
                    let m = &*v.Anonymous.v4AddrMask;
                    format!("{}/{}", std::net::Ipv4Addr::from(m.addr), m.mask.count_ones())
                }
                FWP_V6_ADDR_MASK if !v.Anonymous.v6AddrMask.is_null() => {
                    let m = &*v.Anonymous.v6AddrMask;
                    format!("{}/{}", std::net::Ipv6Addr::from(m.addr), m.prefixLength)
                }
                FWP_BYTE_BLOB_TYPE if !v.Anonymous.byteBlob.is_null() => {
                    let b = &*v.Anonymous.byteBlob;
                    let bytes = if b.size == 0 { &[][..] } else { std::slice::from_raw_parts(b.data, b.size as usize) };
                    // app IDs are UTF-16 device paths
                    let wide: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).take_while(|&c| c != 0).collect();
                    String::from_utf16_lossy(&wide)
                }
                t => format!("(type {t})"),
            }
        };
        format!("{field} {op} {value}")
    }

    /// Remove every rule we ever added (persistent + boot-time). Safe to run
    /// any number of times; reports an error if anything is left.
    pub fn uninstall() -> Result<(), String> {
        let e = Engine::open(false)?;
        e.txn(|| delete_persistent(&e))?;
        remove_boot()?;
        // (outside a transaction) These fail with "in use" while the service
        // still holds its temporary allow-all rule; it removes them itself then.
        if sublayer_exists(&e) {
            let rc = unsafe { FwpmSubLayerDeleteByKey0(e.0, &SUBLAYER) };
            if rc != 0 && rc != FWP_E_SUBLAYER_NOT_FOUND as u32 && rc != FWP_E_IN_USE as u32 {
                check("Removing firewall sublayer", rc)?;
            }
        }
        if provider_exists(&e) {
            let rc = unsafe { FwpmProviderDeleteByKey0(e.0, &PROVIDER) };
            if rc != 0 && rc != FWP_E_PROVIDER_NOT_FOUND as u32 && rc != FWP_E_IN_USE as u32 {
                check("Removing firewall provider", rc)?;
            }
        }
        Ok(())
    }

    /// The block-everything floor (review FINAL-01), read from Windows: our
    /// provider and sublayer as planned; on BOTH IPv4 and IPv6 a persistent,
    /// enabled, unconditional BLOCK in our sublayer; and every filter in our
    /// sublayer or under our provider either that block, our own temporary
    /// allow-all (not persistent), or one of `known` (compared by shape:
    /// action, layer, flags, weight, provider, sublayer, every condition).
    pub fn block_floor(known: &[FilterSpec]) -> Result<(), String> {
        let e = Engine::open(false)?;
        check_provider(&e)?;
        check_sublayer(&e)?;
        for v6 in [false, true] {
            let fam = if v6 { "IPv6" } else { "IPv4" };
            let floor = FilterSpec { index: 0, kind: Kind::Persistent, v6, permit: false, weight: 0, cond: Cond::All };
            let mut has_floor = false;
            let mut odd: Option<String> = None;
            list(&e, v6, None, 0, |f| {
                let ours_provider = !f.providerKey.is_null() && same_guid(unsafe { &*f.providerKey }, &PROVIDER);
                if !ours_provider && !same_guid(&f.subLayerKey, &SUBLAYER) {
                    return; // someone else's filter in someone else's sublayer
                }
                if f.flags & FWPM_FILTER_FLAG_PERSISTENT == 0 && f.action.r#type == FWP_ACTION_PERMIT {
                    // a temporary permit: fine only if it is exactly the guard's own allow-all (V63-05)
                    const RISKY: u32 =
                        FWPM_FILTER_FLAG_DISABLED | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT | FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
                    let weight = if f.weight.r#type == FWP_UINT8 { Some(unsafe { f.weight.Anonymous.uint8 }) } else { None };
                    let owned = super::OWN_ALLOW_ALL.lock().unwrap().clone();
                    if ours_provider
                        && super::is_own_allow_all(
                            f.filterId,
                            &owned,
                            same_guid(&f.subLayerKey, &SUBLAYER),
                            weight,
                            f.numFilterConditions,
                            f.flags & RISKY == 0,
                        )
                    {
                        return;
                    }
                    if odd.is_none() {
                        odd = Some(format!(
                            "a temporary permit in PIA Lite's sublayer or under its name that the guard didn't add (id {})",
                            f.filterId
                        ));
                    }
                    return;
                }
                if check_filter(f, &floor).is_ok() {
                    has_floor = true;
                    return;
                }
                let action = if f.action.r#type == FWP_ACTION_PERMIT {
                    Some(true)
                } else if f.action.r#type == FWP_ACTION_BLOCK {
                    Some(false)
                } else {
                    None
                };
                let recognised = action.is_some_and(|permit| {
                    known
                        .iter()
                        .filter(|k| k.v6 == v6 && k.permit == permit && k.cond.conditions() == f.numFilterConditions)
                        .any(|k| check_filter(f, k).is_ok())
                });
                if !recognised && odd.is_none() {
                    odd = Some(format!("an unrecognised {fam} filter in PIA Lite's sublayer or under its name (id {})", f.filterId));
                }
            })?;
            if let Some(o) = odd {
                return Err(o);
            }
            if !has_floor {
                return Err(format!("no intact persistent block-everything rule for {fam}"));
            }
        }
        Ok(())
    }

    /// Are any of our block rules in Windows? Err = couldn't look (engine not
    /// reachable, access denied...) - never to be read as "none" (V3-01).
    pub fn installed() -> Result<bool, String> {
        let e = Engine::open(false)?;
        for i in 0..MAX_FILTERS {
            if lookup(&e, &key(Kind::Persistent, i))? || lookup(&e, &key(Kind::BootTime, i))? {
                return Ok(true);
            }
        }
        // boot-time rules that are only visible when listed
        let mut found = false;
        for v6 in [false, true] {
            list(&e, v6, None, FWP_FILTER_ENUM_FLAG_BOOTTIME_ONLY, |f| found |= our_key(&f.filterKey).is_some())?;
            list(&e, v6, Some(&PROVIDER), 0, |f| found |= f.flags & FWPM_FILTER_FLAG_PERSISTENT != 0)?;
        }
        Ok(found)
    }

    /// Temporary allow-all (VPN connected, or hotel login). Removed when this
    /// value is dropped - or automatically by Windows if the service dies.
    /// The engine session (its dynamic filters go with it) and their ids.
    /// The ids are known as ours for the filters' whole life (review V64-05):
    /// listed before the change is saved, and forgotten only after the
    /// session - and with it the filters - is closed.
    pub struct OpenAll(Option<Engine>, Vec<u64>);
    impl Drop for OpenAll {
        fn drop(&mut self) {
            drop(self.0.take()); // filters gone first...
            super::OWN_ALLOW_ALL.lock().unwrap().retain(|i| !self.1.contains(i));
            // ...then forgotten
        }
    }

    /// Windows drops the allow-all with the guard's own firewall session
    /// when the process ends - nothing to clean up.
    pub fn reset_open() -> Result<(), String> {
        Ok(())
    }

    // ------------------------------------- plain DNS only through the guard

    /// Windows sends lookups to the guard through PIA's DNS setting
    /// (127.0.0.1). This block makes sure nothing goes AROUND it: while it is
    /// on, plain DNS (port 53) and DNS over TLS (port 853) to any other server
    /// are refused - programs that ask 8.8.8.8 themselves, Windows asking
    /// other adapters' DNS servers in parallel, VMs that borrow this PC's
    /// connection. Allowed: loopback (the guard's proxy), PIA's own programs
    /// and the guard itself (its encrypted DNS to the provider).
    ///
    /// Its own sublayer in a temporary (dynamic) WFP session, no provider: the
    /// internet block's checks don't see it, and if the guard stops, Windows
    /// removes it by itself - it can never leave the PC without DNS.
    /// Two keys, used in turn: a replacement block is built under the other
    /// key while the old one still stands, and only then is the old one
    /// dropped (review G97-03).
    const DNS_SUBLAYERS: [GUID; 2] =
        [GUID::from_u128(0x5a1f7e2c_3b4d_4c8a_9e61_2f0b6d1c7a03), GUID::from_u128(0x5a1f7e2c_3b4d_4c8a_9e61_2f0b6d1c7a04)];
    /// selftest-firewall only: make the next rebuild fail at a stage - 1 opening
    /// the engine, 2 adding the sublayer, 3 adding a rule, 4 checking it.
    static FAIL_NEXT_BUILD: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

    /// One rule of the DNS block, as planned.
    #[derive(Clone)]
    struct DnsRule {
        v6: bool,
        weight: u8,
        permit: bool,
        cond: Cond,
        name: String,
    }

    /// The session holding the DNS block, and the id Windows gave each rule.
    struct DnsBlock {
        e: Engine,
        key: GUID,
        rules: Vec<(u64, DnsRule)>,
    }
    static DNS_BLOCK: std::sync::Mutex<Option<DnsBlock>> = std::sync::Mutex::new(None);

    fn dns_plan() -> Vec<DnsRule> {
        let mut allowed = crate::pia::engine_exes();
        if let Ok(me) = std::env::current_exe() {
            allowed.push(me.to_string_lossy().into_owned());
        }
        let mut v = vec![];
        for v6 in [false, true] {
            let r = |weight: u8, permit: bool, cond: Cond, name: &str| DnsRule { v6, weight, permit, cond, name: name.to_string() };
            v.push(r(15, true, Cond::Loopback, "DNS block: allow loopback (the guard's DNS proxy)"));
            for a in &allowed {
                let file = a.rsplit(['\\', '/']).next().unwrap_or(a);
                v.push(r(14, true, Cond::App(a.clone()), &format!("DNS block: allow {file}")));
            }
            v.push(r(1, false, Cond::RemotePort(53), "DNS block: no plain DNS around the guard"));
            v.push(r(1, false, Cond::RemotePort(853), "DNS block: no DNS over TLS around the guard"));
        }
        v
    }

    fn dns_sublayer_there(e: &Engine, key: &GUID) -> bool {
        let mut s: *mut FWPM_SUBLAYER0 = null_mut();
        let found = unsafe { FwpmSubLayerGetByKey0(e.0, key, &mut s) } == 0 && !s.is_null();
        if found {
            unsafe { FwpmFreeMemory0(&mut s as *mut _ as *mut *mut c_void) };
        }
        found
    }

    fn add_dns_filter(e: &Engine, key: &GUID, r: &DnsRule) -> Result<u64, String> {
        let mut conds = build(&r.cond, r.v6)?;
        let wname = wide(&format!("PIA Lite: {}", r.name));
        let mut f = FWPM_FILTER0::default();
        f.displayData.name = wname.as_ptr() as *mut u16;
        f.layerKey = layer(r.v6);
        f.subLayerKey = *key;
        f.weight = FWP_VALUE0 { r#type: FWP_UINT8, Anonymous: FWP_VALUE0_0 { uint8: r.weight } };
        f.numFilterConditions = conds.list.len() as u32;
        f.filterCondition = if conds.list.is_empty() { null_mut() } else { conds.list.as_mut_ptr() };
        f.action.r#type = if r.permit { FWP_ACTION_PERMIT } else { FWP_ACTION_BLOCK };
        let mut id = 0u64;
        check(&format!("Adding rule '{}'", r.name), unsafe { FwpmFilterAdd0(e.0, &f, null_mut(), &mut id) })?;
        Ok(id)
    }

    /// Is the DNS block exactly as added (review F-03)? Its sublayer; every
    /// rule by its id - layer, sublayer, action, weight, flags, each condition;
    /// and nothing else in the sublayer. Ok(Some(what differs)), Ok(None) =
    /// intact, Err = Windows couldn't be asked.
    fn dns_block_differs(b: &DnsBlock) -> Result<Option<String>, String> {
        if !dns_sublayer_there(&b.e, &b.key) {
            return Ok(Some("its sublayer is gone".into()));
        }
        const RISKY: u32 =
            FWPM_FILTER_FLAG_DISABLED | FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT | FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED;
        for (id, r) in &b.rules {
            let mut f: *mut FWPM_FILTER0 = null_mut();
            let rc = unsafe { FwpmFilterGetById0(b.e.0, *id, &mut f) };
            if rc == FWP_E_FILTER_NOT_FOUND as u32 {
                return Ok(Some(format!("rule '{}' is gone", r.name)));
            }
            if rc != 0 || f.is_null() {
                return Err(format!("could not read DNS block rule '{}' (error 0x{rc:08X})", r.name));
            }
            let held = Got(f);
            let f = unsafe { &*held.0 };
            let action = if r.permit { FWP_ACTION_PERMIT } else { FWP_ACTION_BLOCK };
            let why = if !same_guid(&f.layerKey, &layer(r.v6)) {
                Some("layer")
            } else if !same_guid(&f.subLayerKey, &b.key) {
                Some("sublayer")
            } else if f.action.r#type != action {
                Some("action")
            } else if !weight_is(f, r.weight) {
                Some("weight")
            } else if f.flags & RISKY != 0 {
                Some("flags")
            } else {
                conditions_are(f, &r.cond, r.v6)?
            };
            if let Some(w) = why {
                return Ok(Some(format!("rule '{}' changed ({w})", r.name)));
            }
        }
        let mut count = 0usize;
        for v6 in [false, true] {
            list(&b.e, v6, None, 0, |f| {
                if same_guid(&f.subLayerKey, &b.key) {
                    count += 1;
                }
            })?;
        }
        if count != b.rules.len() {
            return Ok(Some(format!("{count} rules in its sublayer instead of {}", b.rules.len())));
        }
        Ok(None)
    }

    pub fn dns_capture(on: bool) -> Result<(), String> {
        let mut held = DNS_BLOCK.lock().unwrap();
        if !on {
            *held = None; // closing the session removes its sublayer and rules
            return Ok(());
        }
        let mut damaged = String::new();
        if let Some(b) = held.as_ref() {
            match dns_block_differs(b) {
                Ok(None) => return Ok(()),
                Ok(Some(why)) => damaged = why,
                Err(e) => damaged = format!("could not check it: {e}"),
            }
            crate::config::log(&format!("the DNS block isn't intact ({damaged}) - building a new one next to it"));
        }
        // the replacement under the other key, checked, BEFORE the old one goes:
        // if it can't be built, what is left of the old block stays (G97-03)
        let key = match held.as_ref() {
            Some(b) if same_guid(&b.key, &DNS_SUBLAYERS[0]) => DNS_SUBLAYERS[1],
            _ => DNS_SUBLAYERS[0],
        };
        match build_dns_block(key) {
            Ok(b) => {
                *held = Some(b); // drops the old block's session
                Ok(())
            }
            Err(e) if held.is_some() => Err(format!("{e} - the old DNS block ({damaged}) stays in place until it can be replaced")),
            Err(e) => Err(e),
        }
    }

    fn build_dns_block(key: GUID) -> Result<DnsBlock, String> {
        let fail = FAIL_NEXT_BUILD.swap(0, std::sync::atomic::Ordering::SeqCst);
        if fail == 1 {
            return Err("injected: the firewall engine could not be opened (test)".into());
        }
        let e = Engine::open(true)?;
        let plan = dns_plan();
        let sname = wide("PIA Lite: plain DNS only through the guard");
        let rules = e.txn_as("Adding the DNS block", || {
            let s = FWPM_SUBLAYER0 {
                subLayerKey: key,
                displayData: FWPM_DISPLAY_DATA0 { name: sname.as_ptr() as *mut u16, description: null_mut() },
                weight: SUBLAYER_WEIGHT - 1,
                ..Default::default()
            };
            if fail == 2 {
                return Err("injected: the DNS block's sublayer could not be added (test)".to_string());
            }
            check("Adding the DNS block's sublayer", unsafe { FwpmSubLayerAdd0(e.0, &s, null_mut()) })?;
            let mut rules = vec![];
            for r in &plan {
                rules.push((add_dns_filter(&e, &key, r)?, r.clone()));
                if fail == 3 {
                    return Err("injected: a DNS block rule could not be added (test)".to_string());
                }
            }
            Ok(rules)
        })?;
        if fail == 4 {
            return Err("injected: the new DNS block could not be checked (test)".into());
        }
        let b = DnsBlock { e, key, rules };
        if let Some(why) = dns_block_differs(&b)? {
            return Err(format!("the DNS block isn't as planned right after adding it ({why})"));
        }
        Ok(b)
    }

    /// The DNS block is there AND intact (every rule checked, nothing extra).
    pub fn dns_capture_active() -> Result<bool, String> {
        match DNS_BLOCK.lock().unwrap().as_ref() {
            None => Ok(false),
            Some(b) => Ok(dns_block_differs(b)?.is_none()),
        }
    }

    /// selftest-firewall only: damage the DNS block the way someone else
    /// could - 0 = delete its last rule (IPv6, port 853), 1 = add a permit-all
    /// to its sublayer - so the check above can be seen to notice.
    pub fn dns_block_damage_for_test(how: u8) -> Result<(), String> {
        let held = DNS_BLOCK.lock().unwrap();
        let b = held.as_ref().ok_or("no DNS block")?;
        match how {
            0 => {
                let (id, _) = b.rules.last().ok_or("no rules")?;
                check("Deleting a DNS block rule (test)", unsafe { FwpmFilterDeleteById0(b.e.0, *id) })
            }
            _ => {
                let r = DnsRule { v6: false, weight: 15, permit: true, cond: Cond::All, name: "TEST stray permit".into() };
                add_dns_filter(&b.e, &b.key, &r).map(|_| ())
            }
        }
    }

    /// selftest-firewall only: the next rebuild of the DNS block fails at `stage`.
    pub fn dns_block_fail_next_rebuild_for_test(stage: u8) {
        FAIL_NEXT_BUILD.store(stage, std::sync::atomic::Ordering::SeqCst);
    }

    pub fn open_all() -> Result<OpenAll, String> {
        let e = Engine::open(true)?;
        let mut added: Vec<u64> = vec![];
        let r = e.txn(|| {
            for v6 in [false, true] {
                let id = add_filter(&e, None, layer(v6), 15, true, &mut Conds::default(), None, "allow all (VPN connected / hotel login)")?;
                super::OWN_ALLOW_ALL.lock().unwrap().push(id); // known as ours before it can take effect
                added.push(id);
            }
            Ok(())
        });
        if let Err(e) = r {
            super::OWN_ALLOW_ALL.lock().unwrap().retain(|i| !added.contains(i));
            return Err(e);
        }
        Ok(OpenAll(Some(e), added))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The nftables text: highest weight first, the Linux-only preamble
    /// after loopback, every rule tagged; listings parsed without the
    /// chain header (selftest-firewall found that one on a real kernel).
    #[test]
    fn nftables_rules_as_text() {
        let sp = specs(&plan(&["gid:991".into(), "mark:12819".into()], false), Kind::Persistent);
        let s = nft::script(&sp, nft::TABLE, true).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        assert!(lines[1].contains("type filter hook output priority filter; policy accept;"));
        let rules: Vec<&str> = lines.iter().filter(|l| l.starts_with("add rule")).copied().collect();
        assert!(rules[0].contains("fib daddr type local accept") && rules[0].contains("pialite:p:0"), "{}", rules[0]);
        let pre = rules.iter().position(|r| r.contains("pialite:ndp")).unwrap();
        assert!(rules[..pre].iter().all(|r| r.contains("fib daddr type local")), "preamble right after the loopback rules");
        assert!(rules.iter().any(|r| r.contains("meta skgid 991 accept")));
        assert!(rules.iter().any(|r| r.contains("meta mark 12819 accept")));
        assert!(rules.last().unwrap().contains("reject with icmpx admin-prohibited"), "block-everything last");
        assert!(nft::rule_text(&FilterSpec {
            index: 0,
            kind: Kind::Persistent,
            v6: false,
            permit: true,
            weight: 14,
            cond: Cond::App("C:\\x.exe".into())
        })
        .is_err());
        let listing = "table inet pialite {\n\tchain out {\n\t\ttype filter hook output priority filter; policy accept;\n\t\tmeta nfproto ipv4 accept comment \"pialite:p:0\" # handle 4\n\t}\n\tchain open {\n\t}\n}\n";
        assert_eq!(nft::chain_rules(listing, "out").unwrap(), vec![("meta nfproto ipv4 accept comment \"pialite:p:0\"".to_string(), 4)]);
        assert_eq!(nft::chain_rules(listing, "open").unwrap(), vec![]);
        assert_eq!(nft::chain_rules(listing, "missing"), None);
        assert_eq!(nft::comment_of("x accept comment \"pialite:p:3\""), "pialite:p:3");
        let d = nft::dns_capture_script(Some(991));
        assert!(d.contains("meta skgid 991 return") && d.contains("ip daddr 127.0.0.0/8 return") && d.contains("redirect to :53"));
        assert!(d.find("skgid").unwrap() < d.find("redirect").unwrap(), "PIA's own lookups are left alone first");
        assert!(!nft::dns_capture_script(None).contains("skgid"));
    }

    /// Review V63-05: only the guard's own allow-all, exactly as added, is
    /// accepted next to the block floor.
    #[test]
    fn only_the_guards_own_allow_all_is_accepted() {
        let owned = [101, 102];
        assert!(is_own_allow_all(101, &owned, true, Some(15), 0, true));
        assert!(!is_own_allow_all(999, &owned, true, Some(15), 0, true), "not added by this guard");
        assert!(!is_own_allow_all(101, &owned, false, Some(15), 0, true), "another sublayer");
        assert!(!is_own_allow_all(101, &owned, true, Some(14), 0, true), "another weight");
        assert!(!is_own_allow_all(101, &owned, true, None, 0, true), "weight not as added");
        assert!(!is_own_allow_all(101, &owned, true, Some(15), 1, true), "has conditions");
        assert!(!is_own_allow_all(101, &owned, true, Some(15), 0, false), "weakening flags");
        assert!(!is_own_allow_all(101, &[], true, Some(15), 0, true), "the guard holds none right now");
    }

    #[test]
    fn rule_lines_sort_by_number() {
        let mut l: Vec<String> = [
            "temporary allow-all v4",
            "persistent #10 v4",
            "persistent #2  v4",
            "boot-time  #1  v4",
            "persistent #0  v4",
            "boot-time  #0  v6",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        sort_rule_lines(&mut l);
        assert_eq!(
            l,
            [
                "boot-time  #0  v6",
                "boot-time  #1  v4",
                "persistent #0  v4",
                "persistent #2  v4",
                "persistent #10 v4",
                "temporary allow-all v4"
            ]
        );
    }

    fn apps() -> Vec<String> {
        ["pia-service.exe", "pia-wgservice.exe", "pia-openvpn.exe"]
            .iter()
            .map(|f| format!(r"C:\Program Files\Private Internet Access\{f}"))
            .collect()
    }

    #[test]
    fn one_alternative_per_filter() {
        let p = plan(&apps(), true);
        // each program and each LAN range is its own rule
        assert_eq!(p.iter().filter(|r| matches!(r.cond, Cond::App(_))).count(), 3);
        assert_eq!(p.iter().filter(|r| matches!(r.cond, Cond::Subnet4(..))).count(), 6);
        assert_eq!(p.iter().filter(|r| matches!(r.cond, Cond::Subnet6(..))).count(), 3);
        assert!(p.iter().all(|r| r.cond.conditions() <= 1 || r.cond == Cond::Dhcp), "only DHCP has >1 condition (different fields)");
        // the spec carries the exact condition, so values are checked, not just counts (V3-05)
        let sp = specs(&p, Kind::Persistent);
        assert_eq!(sp[1].cond, Cond::App(apps()[0].clone()));
        assert!(sp.iter().any(|f| f.cond == Cond::Subnet4([192, 168, 0, 0], 16)));
        // order: loopback > programs > DHCP > DNS-to-LAN block > LAN > block-all
        let weights: Vec<u8> = p.iter().map(|r| r.weight).collect();
        assert!(weights.windows(2).all(|w| w[0] >= w[1]), "{weights:?}");
        assert_eq!(p[0].cond, Cond::Loopback);
        assert!(!p.last().unwrap().permit && p.last().unwrap().cond == Cond::All);
        assert!(p.iter().any(|r| r.cond == Cond::RemotePort(53) && !r.permit));
        assert!(p[1].name.ends_with("pia-service.exe"));
    }

    #[test]
    fn filter_specs_per_family() {
        let p = plan(&apps(), true);
        let s = specs(&p, Kind::Persistent);
        // v4: loopback + 3 apps + dhcp + dns + 6 lan + block = 13; v6: 1+3+1+1+3+1 = 10
        assert_eq!(s.iter().filter(|f| !f.v6).count(), 13);
        assert_eq!(s.iter().filter(|f| f.v6).count(), 10);
        assert!(s.iter().enumerate().all(|(i, f)| f.index == i as u32), "keys numbered in order");
        assert!(s.len() as u32 <= MAX_FILTERS);
        // even with every PIA program and LAN on, well inside the key range
        let six: Vec<String> = (0..6).map(|i| format!("p{i}.exe")).collect();
        assert!(specs(&plan(&six, true), Kind::Persistent).len() as u32 <= MAX_FILTERS);
        let no_lan = specs(&plan(&apps(), false), Kind::Persistent);
        assert_eq!(no_lan.len(), 2 * (1 + 3 + 1 + 1));
        let b = specs(&boot_plan(), Kind::BootTime);
        assert_eq!(b.len(), 6);
        assert!(boot_plan().iter().all(|r| !matches!(r.cond, Cond::App(_) | Cond::Subnet4(..) | Cond::Subnet6(..))));
        assert_eq!(v4_mask(8), 0xFF00_0000);
        assert_eq!(v4_mask(12), 0xFFF0_0000);
        assert_eq!(v4_mask(32), 0xFFFF_FFFF);
        assert_eq!(v4_mask(0), 0);
    }

    #[cfg(not(windows))]
    #[test]
    fn value_tampering_and_uninspectable_state() {
        let _g = crate::config::tests::ENV_LOCK.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let want = install(&plan(&apps(), true)).unwrap();
        assert!(verify(&want).is_ok());
        // same key, same count, different value -> noticed (V3-05)
        assert!(tamper_value());
        assert!(verify(&want).is_err());
        // "couldn't look" is not "none" (V3-01)
        fail_inspect(true);
        assert!(installed().is_err());
        fail_inspect(false);
        assert_eq!(installed(), Ok(true));
        uninstall().unwrap();
        assert_eq!(installed(), Ok(false));
    }
}
