//! The guard: connects the state machine (policy.rs) to the real world - the
//! firewall rules, PIA, the DNS proxy - and runs the commands from the tray.
//!
//! Rules of the road:
//!  * one mutating command at a time (the `op` lock)
//!  * write the recovery note to disk *before* changing anything in PIA
//!  * after changing PIA, read the setting back; only then call it done
//!  * on any failure, undo what was done and stay protected
//!  * protection comes back first, slow PIA calls after
//!  * a block mode is applied in Windows first and saved after; if either
//!    step fails, both go back to how they were (review N-14)
//!  * from BEFORE a hotel login relaxes PIA's kill switch until it is verified
//!    back, the guard itself blocks whenever the VPN is down - in Startup and
//!    Off mode too (N-06, V3-03, V3-10)
//!  * ending a hotel login re-arms the block before PIA is touched (N-02), and
//!    nothing opens until the restore was tried (V3-03); a late "time is up"
//!    only ever ends the login it belongs to (V3-02)
//!  * commands wait at most 15 s for another command to finish, then answer
//!    "busy" instead of piling up (V3-06)
//!  * the allow-all is decided and changed in ONE step under the policy lock
//!    (lock order: policy -> open), so a stale "open" can never be applied
//!    after a newer "block" (V4-02); it has its own lock, so taking it away is
//!    never stuck behind a slow firewall install or check (V4-02, V4-14)
//!  * what a hotel login must put back is also kept in its own recovery file
//!    (config::Recovery), not only in guard.json (V4-03)

use crate::config::{self, log, Config, Loaded};
use crate::doh::{Doh, Resolve};
use crate::policy::{Event, Policy, Tunnel};
use crate::proxy::Proxy;
use crate::{firewall, pia};
use pialite_common::piactl;
use pialite_common::status::{BlockMode, GuardStatus};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

pub const DNS_ADDR: &str = "127.0.0.1:53";
const SLOW_CHECK: Duration = Duration::from_secs(30);
/// How long a command waits for the one before it (review V3-06).
#[cfg(not(test))]
const OP_WAIT: Duration = Duration::from_secs(15);
#[cfg(test)]
const OP_WAIT: Duration = Duration::from_secs(1);

/// The block rules (only touched with `fw` locked; that can take a while -
/// firewall calls - so nothing urgent waits on it).
#[derive(Default)]
struct Fw {
    /// Exactly what Windows must hold (checked every 30 s, review N-09).
    expected: Vec<firewall::FilterSpec>,
    plan_key: String,
    /// Boot-time rules read back from Windows and found as planned (N-08).
    boot_ok: bool,
    boot_expected: Vec<firewall::FilterSpec>,
    boot_error: String,
}

/// What the status shows about the rules - copied out after each change, so
/// a status request never waits for a firewall call (review V4-14).
#[derive(Default, Clone)]
struct FwView {
    boot_ok: bool,
    boot_error: String,
    error: String,
}

/// Which adapter carried the current VPN connection (review V4-12).
/// What the guard last saw of the network and of PIA's adapter.
#[derive(Default)]
struct TunnelWatch {
    /// The Connected episode being watched (when PIA last became Connected).
    episode: Option<Instant>,
    /// The adapter learned for this connection.
    adapter: Option<String>,
    verdict: Tunnel,
    /// The last look at the adapters failed (the verdict is kept as it was).
    query_failed: bool,
    /// The usable network adapter, as last seen (for the log).
    network: Option<String>,
    network_known: bool,
    /// Does Windows' route to NextDNS go through the learned adapter?
    /// (information only - review V60-08; None = not known)
    route_ok: Option<bool>,
}

/// What a restart of PIA's attempt may do to PIA (a recorder in the tests).
pub trait PiaOps: Send + Sync {
    fn disconnect(&self) -> Result<String, String>;
    fn connect(&self) -> Result<String, String>;
    /// PIA's connection state right now.
    fn state(&self) -> Result<String, String>;
}

struct RealPia;
impl PiaOps for RealPia {
    fn disconnect(&self) -> Result<String, String> {
        pia::disconnect()
    }
    fn connect(&self) -> Result<String, String> {
        pia::connect()
    }
    fn state(&self) -> Result<String, String> {
        pia::state()
    }
}

/// What a restart did (run_restart).
#[derive(Debug, PartialEq)]
#[cfg_attr(not(test), allow(dead_code))]
enum Restart {
    /// Cancelled before anything was sent: not the same stuck attempt any more.
    NotNeeded,
    /// Disconnected; PIA (or the user) is connecting again by itself.
    LeftAlone,
    /// Disconnected, but PIA never reported Disconnected: no blind connect.
    NoDisconnect,
    Stopped,
    Done,
    /// PIA's disconnect failed: nothing else sent.
    DisconnectFailed,
}

/// How long a restart waits for PIA to report Disconnected.
#[cfg(not(test))]
const KICK_WAIT: Duration = Duration::from_secs(10);
#[cfg(test)]
const KICK_WAIT: Duration = Duration::from_millis(600);

/// How long hotel entry waits for its turn at PIA commands (a restart can
/// hold it for its whole wait for Disconnected) before saying "busy".
#[cfg(not(test))]
const PIA_CMD_WAIT: Duration = Duration::from_secs(20);
#[cfg(test)]
const PIA_CMD_WAIT: Duration = Duration::from_millis(800);

/// After a failed reconnect at the end of a hotel login: try again after
/// these delays (review V65-02).
#[cfg(not(test))]
const HOTEL_RETRY: &[Duration] = &[Duration::from_secs(5), Duration::from_secs(15)];
#[cfg(test)]
const HOTEL_RETRY: &[Duration] = &[Duration::from_millis(50), Duration::from_millis(50)];

fn p_state_is(policy: &Mutex<Policy>, want: &str) -> bool {
    policy.lock().unwrap().pia_state().as_deref() == Some(want)
}

/// What the reconnect after a hotel login did.
#[derive(Debug, PartialEq)]
enum HotelReturn {
    /// Not needed (or no longer allowed) - see the log line.
    NotNeeded,
    /// "connect" accepted by PIA.
    Sent,
    /// Every try failed; the user is told to press Connect.
    Failed(String),
}

/// PIA says Connected but none of its adapters is up for this long -> "not found".
const NOT_FOUND_AFTER: Duration = Duration::from_secs(3);

pub struct Guard {
    cfg: Mutex<Config>,
    config_error: Mutex<String>,
    policy: Mutex<Policy>,
    fw: Mutex<Fw>,
    /// Main block rules are in Windows (as last checked).
    /// The block rules are VERIFIED in Windows (status, hotel restore...).
    armed: AtomicBool,
    /// Some PIA Lite block rules are (or may be) in Windows - so the
    /// VPN-connected allow-all must still be added, or a connected VPN would
    /// stay blocked (v0.6.0 lock-out). Never read as "protected" (FINAL-01).
    rules_present: AtomicBool,
    /// The temporary allow-all. Lock order: policy -> open.
    open: Mutex<Option<firewall::OpenAll>>,
    fw_view: Mutex<FwView>,
    tunnel: Mutex<TunnelWatch>,
    /// A restart of PIA's attempt is running (only one at a time).
    kick_running: AtomicBool,
    /// Guard-originated PIA commands one at a time (review FINAL-02): a
    /// restart's connect and the startup connect never overlap.
    pia_cmd: Mutex<()>,
    /// Plain-words "please do this" for the status (V65-02).
    notice: Mutex<String>,
    /// The last rule-change failure logged, and when (log_fw_failure).
    fw_failure_logged: Mutex<Option<(String, Instant)>>,
    proxy: Proxy,
    op: Mutex<()>,
    stop: Arc<AtomicBool>,
    last_probe: Mutex<Option<Instant>>,
    last_slow: Mutex<Option<Instant>>,
    pia_settings: Mutex<Result<pia::Settings, String>>,
    /// PIA's kill switch is not how the user had it (relaxed for a hotel login,
    /// not verified back yet) - the guard blocks like "always" meanwhile.
    restore_pending: AtomicBool,
    restore_failing: AtomicBool,
    ticker: Mutex<Option<JoinHandle<()>>>,
    /// Linux DNS redirect as last applied (None = not yet / to be redone).
    dns_capture: Mutex<Option<bool>>,
}

fn resolver_for(cfg: &Config) -> Arc<dyn Resolve> {
    match Doh::from_config(cfg) {
        Ok(d) => Arc::new(d),
        Err(e) => {
            log(&format!("DoH setup problem: {e}"));
            struct Broken(String);
            impl Resolve for Broken {
                fn resolve(&self, _: &[u8]) -> Result<Vec<u8>, String> {
                    Err(self.0.clone())
                }
            }
            Arc::new(Broken(e))
        }
    }
}

impl Guard {
    pub fn start() -> Arc<Guard> {
        Self::start_with(DNS_ADDR.parse().unwrap(), true)
    }

    /// `watch_pia`: start the piactl monitor/probe threads (off in some tests).
    pub fn start_with(dns_addr: SocketAddr, watch_pia: bool) -> Arc<Guard> {
        // can't tell whether rules are installed -> assume they are (fail closed)
        let loaded = config::load(|| firewall::installed().unwrap_or(true));
        let (cfg, cfg_err) = match loaded {
            Loaded::Ok(c) | Loaded::Fresh(c) => (c, String::new()),
            Loaded::Recovered(c, why) => (c, why),
        };
        let features = cfg.features();
        log(&format!(
            "guard {} starting - block mode {}, encrypted DNS {}, hotel login {}",
            env!("CARGO_PKG_VERSION"),
            cfg.mode.as_str(),
            match (features.dns, cfg.provider()) {
                (false, _) => "off".to_string(),
                (true, "nextdns") => format!("NextDNS (profile {})", if cfg.profile_id.is_empty() { "NOT SET" } else { "set" }),
                (true, p) => p.to_string(),
            },
            if features.hotel { "on" } else { "off" }
        ));
        // what Windows held before this start changes anything: evidence that
        // the stored rules were in force while the guard wasn't running (F51-08)
        log(&firewall::startup_report(&firewall::plan(&pia::engine_exes(), pia::allow_lan_or_safe())));
        // Linux: an allow-all left by a run that ended without cleaning up
        // (Windows drops it with the process by itself)
        if let Err(e) = firewall::reset_open() {
            log(&format!("could not clear an old temporary allow-all: {e}"));
        }
        let now = Instant::now();
        let outstanding = outstanding_restore(&cfg);
        let g = Arc::new(Guard {
            policy: Mutex::new(Policy::new(cfg.mode, cfg.connect_at_boot, now)),
            proxy: if features.dns { Proxy::start(dns_addr, resolver_for(&cfg)) } else { Proxy::off(dns_addr, resolver_for(&cfg)) },
            restore_pending: AtomicBool::new(outstanding.as_deref() == Some("on")),
            restore_failing: AtomicBool::new(false),
            cfg: Mutex::new(cfg),
            config_error: Mutex::new(cfg_err),
            fw: Mutex::new(Fw::default()),
            armed: AtomicBool::new(false),
            rules_present: AtomicBool::new(false),
            open: Mutex::new(None),
            fw_view: Mutex::new(FwView::default()),
            tunnel: Mutex::new(TunnelWatch::default()),
            fw_failure_logged: Mutex::new(None),
            kick_running: AtomicBool::new(false),
            pia_cmd: Mutex::new(()),
            notice: Mutex::new(String::new()),
            op: Mutex::new(()),
            stop: Arc::new(AtomicBool::new(false)),
            last_probe: Mutex::new(None),
            last_slow: Mutex::new(None),
            pia_settings: Mutex::new(pia::read_settings()),
            ticker: Mutex::new(None),
            dns_capture: Mutex::new(None),
        });
        // left over from a hotel login before a restart: PIA's kill switch isn't trusted yet
        g.policy.lock().unwrap().set_strict(g.restore_pending.load(Ordering::Relaxed));
        g.sync_rules(true);

        if watch_pia {
            let g2 = g.clone();
            piactl::monitor("connectionstate", move |v| g2.observe(v.as_deref(), Instant::now()));
            let g3 = g.clone();
            std::thread::spawn(move || {
                while !g3.stop.load(Ordering::Relaxed) {
                    let now = Instant::now();
                    let last = *g3.last_probe.lock().unwrap();
                    if g3.policy.lock().unwrap().needs_probe(now, last) {
                        *g3.last_probe.lock().unwrap() = Some(now);
                        let r = pia::state().ok();
                        g3.observe(r.as_deref(), now); // stamped with when the check *started*
                    }
                    std::thread::sleep(Duration::from_millis(500));
                }
            });
        }
        let g4 = g.clone();
        let t = std::thread::spawn(move || {
            while !g4.stop.load(Ordering::Relaxed) {
                #[cfg(test)]
                if tests::TICK_PAUSED.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
                g4.tick();
                // a second between ticks; a new connection's adapter is looked
                // for every 200 ms meanwhile (Always mode waits for it)
                for _ in 0..5 {
                    std::thread::sleep(Duration::from_millis(200));
                    #[cfg(test)]
                    if tests::TICK_PAUSED.load(Ordering::SeqCst) {
                        break;
                    }
                    if g4.tunnel_checking() {
                        g4.watch_network();
                    }
                }
            }
        });
        *g.ticker.lock().unwrap() = Some(t);
        g
    }

    /// Service stopping. Persistent + boot-time rules stay (they protect the
    /// next boot); the temporary allow-all goes away with our process.
    /// Joined: the 1-second ticker (so no rule or hotel decision of its own
    /// runs after this). The probe thread ends at its next check (<= 0.5 s),
    /// piactl helpers are killed, and background PIA calls (reconnect, end of
    /// a hotel login) check the stop flag before they start; one already
    /// running may still finish its piactl call (review V3-12).
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.ticker.lock().unwrap().take() {
            let _ = t.join(); // at most ~1 s
        }
        self.proxy.stop();
        if self.dns_capture.lock().unwrap().is_some() {
            // normal DNS while the guard is away (Linux; Windows: PIA's setting)
            let _ = firewall::dns_capture(false);
        }
        piactl::shutdown();
        log("guard stopped");
    }

    /// Wait (bounded) for the command before this one to finish.
    fn op_lock(&self) -> Result<MutexGuard<'_, ()>, String> {
        let until = Instant::now() + OP_WAIT;
        loop {
            match self.op.try_lock() {
                Ok(g) => return Ok(g),
                Err(TryLockError::Poisoned(p)) => return Ok(p.into_inner()),
                Err(TryLockError::WouldBlock) if Instant::now() >= until => return Err(BUSY.into()),
                Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(25)),
            }
        }
    }

    /// The mode that decides the rules right now (Off/Startup act as Always
    /// while PIA's kill switch isn't back after a hotel login).
    fn effective_mode(&self) -> BlockMode {
        self.policy.lock().unwrap().effective()
    }

    /// PIA's kill switch is / is no longer relaxed by a hotel login. Puts the
    /// rules in Windows in line right away (Err = the block couldn't be set).
    fn set_pending(&self, on: bool) -> Result<(), String> {
        self.restore_pending.store(on, Ordering::Relaxed);
        self.policy.lock().unwrap().set_strict(on);
        self.enforce(self.effective_mode(), false)
    }

    /// After hotel login #`gen` (the user ended it, or it ran out): reconnect -
    /// one PIA command at a time like the others (review V63-04).
    fn spawn_hotel_reconnect(self: &Arc<Self>, gen: u64) {
        let g = self.clone();
        std::thread::spawn(move || {
            g.run_hotel_reconnect(gen, &RealPia, HOTEL_RETRY);
        });
    }

    /// When it's this worker's turn: reconnect only if that login is still
    /// the latest and over, the kill switch restore is done, the guard isn't
    /// stopping, the user hasn't pressed Disconnect, and PIA isn't already
    /// connected or connecting. "Already connected" must come from a report
    /// made AFTER the login ended; without one PIA is asked (review V64-02),
    /// and the decision then uses the NEWEST accepted report - PIA's answer,
    /// or a monitor report that arrived while asking (V65-01).
    /// A failed connect is tried again after each delay in `retry` (each time
    /// checking everything again, since a failed command may still have
    /// worked); if all fail, the status tells the user to press Connect
    /// (V65-02).
    fn run_hotel_reconnect(&self, gen: u64, ops: &dyn PiaOps, retry: &[Duration]) -> HotelReturn {
        let mut last_err = String::new();
        for attempt in 0..=retry.len() {
            if attempt > 0 {
                std::thread::sleep(retry[attempt - 1]);
            }
            #[cfg(test)]
            tests::pause_before_pia_cmd();
            let _cmd = self.pia_cmd.lock().unwrap();
            if self.policy.lock().unwrap().fresh_state(Instant::now()).is_none() {
                // no report since the login ended: ask PIA (not under the policy lock)
                let asked = Instant::now();
                if let Ok(st) = ops.state() {
                    self.observe(Some(st.trim()), asked); // ignored if a newer report came meanwhile
                }
            }
            let why_not = {
                let p = self.policy.lock().unwrap();
                let now = Instant::now();
                let st = p.fresh_state(now).flatten(); // the newest accepted report (V65-01)
                if self.stop.load(Ordering::Relaxed) {
                    Some("the guard is stopping")
                } else if p.hotel_gen() != gen || p.hotel_active(now) {
                    Some("a newer hotel login started")
                } else if p.restoring() {
                    Some("PIA's kill switch is still being put back")
                } else if p.user_off() {
                    Some("the user pressed Disconnect")
                } else if st.as_deref() == Some("Connected") || crate::policy::trying(st.as_deref()) {
                    Some("PIA is already connected or connecting")
                } else {
                    None
                }
            };
            if let Some(w) = why_not {
                log(&format!("hotel login #{gen}: not reconnecting - {w}"));
                if !last_err.is_empty() {
                    self.set_notice(String::new());
                }
                return HotelReturn::NotNeeded;
            }
            match ops.connect() {
                Ok(_) => {
                    if !last_err.is_empty() {
                        self.set_notice(String::new());
                    }
                    return HotelReturn::Sent;
                }
                Err(e) => {
                    log(&format!(
                        "hotel login #{gen}: reconnect failed ({e}){}",
                        if attempt < retry.len() { " - trying again" } else { "" }
                    ));
                    last_err = e;
                }
            }
        }
        self.set_notice(format!("The VPN didn't reconnect after the hotel login ({last_err}) - press Connect"));
        HotelReturn::Failed(last_err)
    }

    fn set_notice(&self, n: String) {
        *self.notice.lock().unwrap() = n;
    }

    /// Hotel entry's turn at PIA commands (review V64-04), within a bound.
    fn pia_cmd_within(&self, limit: Duration) -> Result<MutexGuard<'_, ()>, String> {
        let until = Instant::now() + limit;
        loop {
            match self.pia_cmd.try_lock() {
                Ok(g) => return Ok(g),
                Err(TryLockError::Poisoned(p)) => return Ok(p.into_inner()),
                Err(TryLockError::WouldBlock) if Instant::now() >= until => {
                    return Err("busy: the guard is still talking to PIA (a reconnect) - try again in a moment".into())
                }
                Err(TryLockError::WouldBlock) => std::thread::sleep(Duration::from_millis(25)),
            }
        }
    }

    /// The startup/wake connect: one PIA command at a time, and only if PIA is
    /// still Disconnected and the user hasn't pressed Disconnect (FINAL-02).
    fn spawn_connect(self: &Arc<Self>) {
        let g = self.clone();
        std::thread::spawn(move || {
            let _cmd = g.pia_cmd.lock().unwrap();
            // the user may have pressed Disconnect, or PIA started meanwhile
            let still = {
                let p = g.policy.lock().unwrap();
                // a FRESH Disconnected (same rule as the hotel return, V64-02)
                !p.user_off() && p.fresh_state(Instant::now()).flatten().as_deref() == Some("Disconnected")
            };
            if !g.stop.load(Ordering::Relaxed) && still {
                if let Err(e) = pia::connect() {
                    log(&e);
                }
            }
        });
    }

    pub(crate) fn cfg(&self) -> Config {
        self.cfg.lock().unwrap().clone()
    }

    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn allowed_sids(&self) -> Vec<String> {
        self.cfg.lock().unwrap().allowed_sids.clone()
    }

    /// Change settings: saved to disk first; memory only changes if that worked.
    fn update_cfg(&self, f: impl FnOnce(&mut Config)) -> Result<(), String> {
        let mut c = self.cfg.lock().unwrap();
        let mut next = c.clone();
        f(&mut next);
        config::save(&next)?;
        *c = next;
        self.config_error.lock().unwrap().clear();
        Ok(())
    }

    fn log_events(ev: &[Event]) {
        for e in ev {
            match e {
                // "block lifted" is logged where the allow-all really goes in (apply_open)
                Event::HandedOff => log("PIA connected - hand-off done (in startup mode PIA's own kill switch takes over from here)"),
                Event::Rearmed(why) => log(&format!("{why} - blocking until the VPN is connected")),
                Event::HotelExpired(n) => log(&format!("hotel login #{n}: time is up")),
            }
        }
    }

    fn observe(&self, state: Option<&str>, at: Instant) {
        let (ev, changed) = {
            let mut p = self.policy.lock().unwrap();
            let before = p.pia_state();
            let ev = p.observe(state, at);
            (ev, p.pia_state() != before)
        };
        if state == Some("Connected") && p_state_is(&self.policy, "Connected") {
            self.set_notice(String::new()); // e.g. "press Connect" is done
        }
        if changed {
            // a timeline for diagnosing slow connects (a few lines per connect)
            log(&format!("PIA: {}", state.unwrap_or("service not reachable")));
            // VPN came up / went down: old NextDNS connections are likely dead
            self.proxy.reset();
            if state == Some("Connected") {
                // check the adapter now, not at the next tick (Always mode
                // opens only once it is seen up), and get NextDNS ready
                self.watch_network();
                self.proxy.warm();
            }
        }
        Self::log_events(&ev);
        self.apply_open();
    }

    /// Make the temporary allow-all match the state machine. The decision and
    /// the change happen while the policy is locked, so no newer decision
    /// (a hotel end, a disconnect) can slip in between (review V4-02).
    fn apply_open(&self) {
        let p = self.policy.lock().unwrap();
        let want = p.want_open(Instant::now());
        #[cfg(test)]
        tests::pause_point();
        let mut open = self.open.lock().unwrap();
        let want = want && self.rules_present.load(Ordering::SeqCst);
        if want && open.is_none() {
            match firewall::open_all() {
                Ok(o) => {
                    *open = Some(o);
                    log(if p.hotel_active(Instant::now()) { "block lifted (hotel login)" } else { "block lifted (VPN connected)" });
                }
                Err(e) => {
                    log(&format!("could not lift the block: {e}"));
                    self.fw_view.lock().unwrap().error = e;
                }
            }
        } else if !want && open.is_some() {
            *open = None;
        }
        drop(open);
        drop(p);
    }

    /// `armed`: verified; `present`: rules (may) be there. Verified implies present.
    fn set_rules(&self, armed: bool, present: bool) {
        self.rules_present.store(present || armed, Ordering::SeqCst);
        self.armed.store(armed, Ordering::SeqCst);
    }

    fn set_fw_error(&self, e: String) {
        self.fw_view.lock().unwrap().error = e;
    }

    /// A failed rule change: logged with a look at who else uses PIA Lite's
    /// firewall objects - the first time, when it changes, and then every 10
    /// minutes (it is retried every 30 s).
    fn log_fw_failure(&self, msg: &str) {
        let mut last = self.fw_failure_logged.lock().unwrap();
        let due = match &*last {
            Some((m, at)) => m != msg || at.elapsed() >= Duration::from_secs(600),
            None => true,
        };
        if due {
            *last = Some((msg.to_string(), Instant::now()));
            drop(last);
            log(msg);
            log(&format!("firewall details: {}", firewall::diagnose()));
        }
    }

    /// One look at the network adapters (once a second; right away when PIA
    /// reports Connected; every 200 ms while a new connection is checked):
    /// - is there a usable network? (PIA is asked to connect once there is)
    /// - for a VPN connection: is PIA's adapter for it up? Learned afresh for
    ///   every connection; "not found" if none of PIA's adapters is up within
    ///   3 s; "down" if the learned one goes down or disappears (V4-12, F51-07).
    ///   A failed look keeps the last verdict (status: query-failed).
    fn watch_network(&self) {
        let snap = crate::netif::snapshot();
        let now = Instant::now();
        // where the route to NextDNS goes (the guard's own DoH traffic)
        let probe = self
            .cfg()
            .doh_bootstrap
            .iter()
            .find_map(|a| a.parse::<std::net::Ipv4Addr>().ok())
            .unwrap_or(std::net::Ipv4Addr::new(45, 90, 28, 0));
        let (connected, episode) = {
            let mut p = self.policy.lock().unwrap();
            p.set_network(snap.as_ref().map(|s| s.network.is_some()), now);
            (p.pia_state().as_deref() == Some("Connected"), p.state_since())
        };
        let mut notes = vec![];
        let verdict = {
            let mut w = self.tunnel.lock().unwrap();
            if let Some(s) = &snap {
                if !w.network_known || s.network != w.network {
                    notes.push(match &s.network {
                        Some(n) => format!("network is up ({n})"),
                        None => "no usable network (no adapter with an address and a gateway)".to_string(),
                    });
                    w.network = s.network.clone();
                    w.network_known = true;
                }
            }
            if !connected {
                let keep = (w.network.clone(), w.network_known);
                *w = TunnelWatch { network: keep.0, network_known: keep.1, ..Default::default() };
                None
            } else {
                if w.episode != episode {
                    // a new connection: learn its adapter afresh
                    w.episode = episode;
                    w.adapter = None;
                    w.verdict = Tunnel::Unchecked;
                }
                match &snap {
                    None => {
                        w.query_failed = true;
                        Some(w.verdict) // no new conclusion
                    }
                    Some(s) => {
                        w.query_failed = false;
                        let v = match &w.adapter {
                            None => match s.pia.iter().find(|a| a.up) {
                                Some(a) => {
                                    notes.push(format!("VPN adapter '{}' is up - watching it", a.name));
                                    w.adapter = Some(a.name.clone());
                                    Tunnel::Up
                                }
                                None if episode.is_some_and(|t| now.saturating_duration_since(t) >= NOT_FOUND_AFTER) => Tunnel::NotFound,
                                None => Tunnel::Unchecked,
                            },
                            Some(name) if s.pia.iter().any(|a| &a.name == name && a.up) => Tunnel::Up,
                            Some(_) => Tunnel::Down,
                        };
                        // information only: is the adapter also where Windows routes NextDNS?
                        let route = if v == Tunnel::Up {
                            let idx = s.pia.iter().find(|a| Some(&a.name) == w.adapter.as_ref()).map(|a| a.index);
                            crate::netif::route_index(probe).zip(idx).map(|(r, i)| r == i)
                        } else {
                            None
                        };
                        if route != w.route_ok && route.is_some() {
                            notes.push(if route == Some(true) {
                                "the route to the internet (NextDNS) goes through PIA's adapter".to_string()
                            } else {
                                "NOTE: encrypted DNS is NOT routed through PIA's adapter (split tunnel? another VPN?) - shown in the status"
                                    .to_string()
                            });
                        }
                        w.route_ok = route;
                        if v != w.verdict {
                            let name = w.adapter.clone().unwrap_or_default();
                            match (w.verdict, v) {
                                (_, Tunnel::Down) => notes.push(format!(
                                    "VPN adapter '{name}' went down while PIA still says Connected - blocking like disconnected"
                                )),
                                (Tunnel::Down, Tunnel::Up) => notes.push(format!("VPN adapter '{name}' is up again")),
                                (_, Tunnel::NotFound) => notes.push(
                                    "PIA says Connected, but none of its network adapters is up - Always mode keeps blocking".to_string(),
                                ),
                                _ => {}
                            }
                            w.verdict = v;
                        }
                        Some(v)
                    }
                }
            }
        };
        for n in notes {
            log(&n);
        }
        if let Some(v) = verdict {
            let changed = {
                let mut p = self.policy.lock().unwrap();
                // compare with the policy's own value: it resets it when PIA's state changes
                let changed = p.tunnel() != v && p.pia_state().as_deref() == Some("Connected") && p.state_since() == episode;
                if changed {
                    p.set_tunnel(v);
                }
                changed
            };
            if changed {
                self.apply_open();
            }
        }
    }

    /// Is a new VPN connection's adapter still being looked for?
    fn tunnel_checking(&self) -> bool {
        let p = self.policy.lock().unwrap();
        p.pia_state().as_deref() == Some("Connected") && p.tunnel() == Tunnel::Unchecked
    }

    /// Restart PIA's connection attempt number `gen` on a worker thread - at
    /// most one at a time (a second request while one runs is dropped).
    fn restart_attempt(self: &Arc<Self>, gen: u64, why: impl Into<String>, ops: Arc<dyn PiaOps>) {
        if self.kick_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let g = self.clone();
        let why = why.into();
        std::thread::spawn(move || {
            g.run_restart(gen, &why, ops.as_ref());
            g.kick_running.store(false, Ordering::SeqCst);
        });
    }

    /// The restart itself (review V60-01). Checked again right before PIA is
    /// disconnected: still the same stuck attempt, still the guard's business
    /// (not if PIA connected meanwhile, the user disconnected, block off,
    /// hotel login, restore). Then it waits for PIA to REPORT Disconnected:
    /// a connect sent while it is still disconnecting is ignored by PIA, and
    /// nothing is sent blindly after a timeout. Then checked once more before
    /// connecting. Returns what it did, for the log and the tests.
    fn run_restart(&self, gen: u64, why: &str, ops: &dyn PiaOps) -> Restart {
        if self.stop.load(Ordering::Relaxed) || !self.policy.lock().unwrap().kick_still_valid(gen, Instant::now()) {
            return Restart::NotNeeded;
        }
        #[cfg(test)]
        tests::pause_before_pia_cmd();
        let _cmd = self.pia_cmd.lock().unwrap();
        // again, now that it's this worker's turn: waiting for another PIA
        // command can take seconds, and PIA may have connected, the user may
        // have pressed Disconnect, the block may be off... (review V63-01)
        if self.stop.load(Ordering::Relaxed) || !self.policy.lock().unwrap().kick_still_valid(gen, Instant::now()) {
            return Restart::NotNeeded;
        }
        log(why);
        let sent = Instant::now();
        if let Err(e) = ops.disconnect() {
            // never connect after a disconnect that didn't go through: a
            // "Disconnected" seen next could be someone else's (FINAL-02)
            log(&format!("restart: PIA's disconnect failed ({e}) - not reconnecting"));
            return Restart::DisconnectFailed;
        }
        let until = sent + KICK_WAIT;
        loop {
            if self.stop.load(Ordering::Relaxed) {
                return Restart::Stopped;
            }
            let now = Instant::now();
            let p = self.policy.lock().unwrap();
            if p.may_reconnect(sent, now) {
                break;
            }
            // someone (PIA itself, the user) is connecting/connected again: leave it
            if let Some((Some(st), at)) = p.last_observed() {
                if at >= sent && (st == "Connected" || st == "Connecting" || st == "Reconnecting") {
                    drop(p);
                    log("restart: PIA is connecting/connected again on its own - not sending another connect");
                    return Restart::LeftAlone;
                }
            }
            if p.last_observed().is_some_and(|(st, at)| at >= sent && st.as_deref() == Some("Disconnected")) {
                // Disconnected, but no longer the guard's business (block off, hotel, restore)
                drop(p);
                log("restart: PIA is disconnected, but the block no longer waits for it - not reconnecting");
                return Restart::NotNeeded;
            }
            drop(p);
            if now >= until {
                log("restart: PIA did not report Disconnected in time - not reconnecting blindly (the next check tries again)");
                return Restart::NoDisconnect;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        // the last check, right before connecting (FINAL-02): still allowed,
        // and no newer attempt started by anyone
        {
            let p = self.policy.lock().unwrap();
            if self.stop.load(Ordering::Relaxed) || !p.may_reconnect(sent, Instant::now()) || p.attempt_gen() != gen {
                drop(p);
                log("restart: things changed just before reconnecting - not reconnecting");
                return Restart::NotNeeded;
            }
        }
        // What can still happen between that check and PIA receiving the
        // command is harmless: PIA ignores connect while connected, and a
        // block turned off doesn't make a VPN connection unwanted.
        if let Err(e) = ops.connect() {
            log(&e);
        }
        Restart::Done
    }

    // ---------------------------------------------------------------- rules

    /// Make the rules in Windows match the current mode (repairs drift).
    fn sync_rules(&self, force: bool) {
        let _ = self.enforce(self.effective_mode(), force);
    }

    /// Make the rules in Windows match `mode`. Also checks the rules really
    /// are in Windows exactly as planned - action, layer, flags, weight,
    /// conditions, nothing extra (audit P2-20, review N-08/N-09) - and
    /// repairs them. Err = the main block could not be put in place/removed.
    fn enforce(&self, mode: BlockMode, force: bool) -> Result<(), String> {
        let cfg = self.cfg();
        let mut result = Ok(());
        {
            let mut fw = self.fw.lock().unwrap();
            let armed = self.armed.load(Ordering::SeqCst);
            if mode != BlockMode::Off {
                let (apps, lan) = (pia::engine_exes(), pia::allow_lan_or_safe());
                let plan = firewall::plan(&apps, lan);
                let key = format!("{plan:?}");
                // (a different plan is reinstalled below anyway)
                let drift = if armed && key == fw.plan_key { firewall::verify(&fw.expected).err() } else { None };
                if let Some(d) = &drift {
                    log(&format!("block rules in the firewall don't match the plan ({d}) - putting them back"));
                }
                if force || drift.is_some() || !armed || key != fw.plan_key {
                    match firewall::install(&plan) {
                        Ok(specs) => {
                            if !armed || key != fw.plan_key {
                                log(&format!("block rules in place ({} filters, read back and checked)", specs.len()));
                            }
                            self.set_rules(true, true);
                            fw.expected = specs;
                            fw.plan_key = key;
                            self.set_fw_error(String::new());
                        }
                        Err(e) => {
                            // What is in Windows NOW decides, not what we hoped
                            // to put there. The change is all-or-nothing, so the
                            // previous rules usually still stand - and they block.
                            // Treating them as "no rules" left the internet
                            // blocked with the VPN connected (v0.6.0 lock-out).
                            // But only VERIFIED rules count as protection
                            // (review FINAL-01); rules that are merely there
                            // still get the VPN-connected allow-all.
                            let want = firewall::specs(&plan, firewall::Kind::Persistent);
                            let (armed_now, present, note) = if firewall::verify(&want).is_ok() {
                                fw.expected = want;
                                fw.plan_key = key.clone();
                                (
                                    true,
                                    true,
                                    "the rules already in the firewall match the plan - kept, and the block works as usual".to_string(),
                                )
                            } else if !fw.expected.is_empty() && firewall::verify(&fw.expected).is_ok() {
                                (
                                    true,
                                    true,
                                    "the rules the guard last verified are still in the firewall, exactly - kept (verified); trying again"
                                        .to_string(),
                                )
                            } else {
                                let known = firewall::known_shapes(&apps, lan, &fw.expected);
                                match firewall::block_floor(&known) {
                                    Ok(()) => (
                                        true,
                                        true,
                                        "older PIA Lite rules are in the firewall and their block-everything rules for IPv4 and IPv6 check out (nothing unrecognised) - kept; trying again".to_string(),
                                    ),
                                    Err(why) => match firewall::installed() {
                                        Ok(false) => (false, false, "no PIA Lite rules are in the firewall - nothing is blocked by PIA Lite".to_string()),
                                        Ok(true) => (
                                            false,
                                            true,
                                            format!("PIA Lite rules are in the firewall but the protection can NOT be confirmed ({why}); the internet still opens while the VPN is connected"),
                                        ),
                                        Err(x) => (
                                            false,
                                            true,
                                            format!("the firewall's rules couldn't be read ({x}) - the protection can NOT be confirmed; the internet still opens while the VPN is connected"),
                                        ),
                                    },
                                }
                            };
                            self.set_rules(armed_now, present);
                            self.log_fw_failure(&format!("could not set block rules: {e} - {note}"));
                            self.set_fw_error(format!("block rules could not be refreshed: {e} ({note})"));
                            result = Err(e);
                        }
                    }
                }
                if cfg.boot_time_rules {
                    let drift = fw.boot_ok && firewall::verify(&fw.boot_expected).is_err();
                    if drift {
                        log("boot-time rules don't match the plan - putting them back");
                    }
                    if force || drift || (!fw.boot_ok && fw.boot_error.is_empty()) {
                        match firewall::install_boot(&firewall::boot_plan()) {
                            Ok(specs) => {
                                if !fw.boot_ok {
                                    log(&format!("boot-time rules in place ({} filters, read back and checked)", specs.len()));
                                }
                                fw.boot_ok = true;
                                fw.boot_expected = specs;
                                fw.boot_error.clear();
                            }
                            Err(e) => {
                                log(&format!("boot-time rules not accepted by the system: {e} (the main block still works)"));
                                fw.boot_ok = false;
                                fw.boot_expected.clear();
                                fw.boot_error = e;
                            }
                        }
                    }
                } else if fw.boot_ok || force {
                    if let Err(e) = firewall::remove_boot() {
                        log(&e);
                    }
                    fw.boot_ok = false;
                    fw.boot_expected.clear();
                }
            } else if armed || fw.boot_ok || force {
                // rules first, then the allow-all, then again for the sublayer:
                // no moment where the block bites on the way out
                let r = firewall::uninstall();
                self.set_rules(false, false); // before the allow-all goes (apply_open checks it)
                *self.open.lock().unwrap() = None;
                match r.and_then(|_| firewall::uninstall()) {
                    Ok(()) => {
                        if armed {
                            log("block rules removed");
                        }
                        *fw = Fw::default();
                        self.set_fw_error(String::new());
                    }
                    Err(e) => {
                        log(&format!("could not remove block rules: {e}"));
                        // still in Windows: say so
                        let left = firewall::installed().unwrap_or(true);
                        self.set_rules(left, left);
                        self.set_fw_error(e.clone());
                        result = Err(e);
                    }
                }
            }
            let mut v = self.fw_view.lock().unwrap();
            v.boot_ok = fw.boot_ok;
            v.boot_error = fw.boot_error.clone();
        }
        self.apply_open();
        result
    }

    // ----------------------------------------------------------------- loop

    fn tick(self: &Arc<Self>) {
        // first: is there a network / is PIA's adapter up (decides the rest)
        self.watch_network();
        let now = Instant::now();
        let (mut ev, auto_connect, kick, net_kick, expired) = {
            let mut p = self.policy.lock().unwrap();
            let ev = p.tick(now);
            // "is it due?" and "end it" in one step (review V4-01)
            let expired = p.expire_hotel_if_due(now);
            // a restart in progress connects itself; don't race it (FINAL-02)
            let ac = !self.kick_running.load(Ordering::SeqCst) && p.should_auto_connect(now);
            let kick = p.should_kick(now).then(|| (p.kicks(), p.attempt_gen()));
            let net_kick = p.should_net_kick(now).then(|| p.attempt_gen());
            (ev, ac, kick, net_kick, expired)
        };
        if let Some(gen) = net_kick {
            self.restart_attempt(
                gen,
                "the network came up while PIA was still retrying - restarting its attempt now (PIA waits up to 10 s between retries)",
                Arc::new(RealPia),
            );
        }
        if let Some((n, gen)) = kick {
            let why = format!(
                "PIA has been connecting for {} s while the internet is blocked - asking it to reconnect ({n}/{})",
                crate::policy::KICK_AFTER.as_secs(),
                crate::policy::KICKS_MAX
            );
            self.restart_attempt(gen, why, Arc::new(RealPia));
        }
        if let Some(gen) = expired {
            ev.push(Event::HotelExpired(gen));
        }
        Self::log_events(&ev);
        if let Some(gen) = expired {
            // protection back right away (re-armed); PIA calls happen off this thread
            self.apply_open();
            let g = self.clone();
            std::thread::spawn(move || g.end_expired_hotel(gen));
        }
        if auto_connect {
            log("asking PIA to connect (after startup/wake)");
            self.spawn_connect();
        }
        self.apply_open();
        self.sync_dns_capture(false);

        let slow_due = self.last_slow.lock().unwrap().is_none_or(|t| now.saturating_duration_since(t) >= SLOW_CHECK);
        if slow_due {
            // Only between commands: a mode change applies its rules before it
            // saves the mode, and this check must not "repair" them back to
            // the old mode in between. Busy -> try again next second.
            if let Ok(_op) = self.op.try_lock() {
                *self.last_slow.lock().unwrap() = Some(now);
                *self.pia_settings.lock().unwrap() = pia::read_settings();
                self.sync_rules(false);
                self.sync_dns_capture(true);
                let unfinished = self.restore_pending.load(Ordering::Relaxed) || outstanding_restore(&self.cfg()).is_some();
                if unfinished && !self.policy.lock().unwrap().hotel_active(now) {
                    let _ = self.try_restore();
                }
            }
        }
    }

    /// Linux: plain DNS is redirected to the proxy only while the proxy is
    /// listening - a proxy that could not start (port 53 taken by another
    /// program) must not take the computer's DNS down with it. `recheck`:
    /// also look whether the rules are really still there (every 30 s).
    fn sync_dns_capture(&self, recheck: bool) {
        if !cfg!(any(test, target_os = "linux")) {
            return;
        }
        let want = self.cfg().features().dns && self.proxy.stats.listening.load(Ordering::Relaxed);
        let mut have = self.dns_capture.lock().unwrap();
        if recheck && *have == Some(true) {
            match firewall::dns_capture_active() {
                Ok(true) => {}
                Ok(false) => {
                    log("the DNS redirect rules were missing - adding them again");
                    *have = None;
                }
                Err(e) => log(&format!("could not check the DNS redirect rules: {e}")),
            }
        }
        if *have == Some(want) {
            return;
        }
        let was = *have;
        if let Err(e) = firewall::dns_capture(want) {
            // logged once; a missing redirect is found again by the 30 s check
            log(&format!("could not {} the DNS redirect: {e}", if want { "add" } else { "remove" }));
        } else if want {
            log("plain DNS from programs now goes to the encrypted DNS proxy");
        } else if was == Some(true) {
            log("DNS redirect removed (the proxy is not listening)");
        }
        *have = Some(want);
    }

    /// PC going to sleep / waking up (incl. Fast Startup).
    #[cfg_attr(not(windows), allow(dead_code))]
    pub fn rearm(&self, why: &'static str) {
        let ev = self.policy.lock().unwrap().rearm(Instant::now(), why);
        Self::log_events(&ev);
        self.proxy.reset();
        *self.last_probe.lock().unwrap() = None; // check PIA again right away
        self.apply_open();
    }

    // ---------------------------------------------------------------- hotel

    /// Captive-portal login (audit P1-06): check first, write the recovery note,
    /// let the guard take over, change PIA and confirm, then open. Any failure
    /// is rolled back.
    pub fn hotel_start(&self) -> Result<String, String> {
        if !self.cfg().features().hotel {
            return Err("hotel login is turned off (it can be turned on in PIA Lite's setup)".into());
        }
        let _op = self.op_lock()?;
        // PIA's kill switch and connection are changed below: in turn with the
        // guard's other PIA commands, never in the middle of a reconnect
        // (review V64-04). Lock order everywhere: op -> pia_cmd -> policy.
        #[cfg(test)]
        tests::pause_before_pia_cmd();
        let _cmd = self.pia_cmd_within(PIA_CMD_WAIT)?;
        let now = Instant::now();
        let minutes = self.cfg().hotel_minutes;
        let until = now + Duration::from_secs(minutes as u64 * 60);
        {
            let mut p = self.policy.lock().unwrap();
            if p.hotel_active(now) {
                p.start_hotel(now, until);
                return Ok(format!("hotel login extended to {minutes} min"));
            }
        }
        // An earlier login's change is undone FIRST - otherwise its "kill switch
        // was on" note would be overwritten with today's relaxed value (V3-02).
        let unfinished = outstanding_restore(&self.cfg()).is_some() || self.restore_pending.load(Ordering::Relaxed);
        if unfinished && self.try_restore().is_err() {
            return Err("PIA's kill switch from the last hotel login isn't back yet - try again in a minute".into());
        }
        let state = pia::state().map_err(|e| format!("PIA's service isn't answering ({e})"))?;
        let ks = pia::read_settings()?.killswitch;

        // the recovery record first (its own file, V4-03), then the note in guard.json
        let next = self.policy.lock().unwrap().hotel_gen() + 1;
        config::save_recovery(&config::Recovery::new(next, &ks))?;
        if let Err(e) = self.update_cfg(|c| {
            c.hotel_active = true;
            c.hotel_saved_killswitch = ks.clone();
        }) {
            let _ = config::clear_recovery();
            return Err(e);
        }
        let rollback = |why: String| -> String {
            if ks == "on" {
                let _ = pia::set_killswitch("on");
            }
            let _ = self.try_restore();
            log(&format!("hotel login cancelled: {why}"));
            why
        };
        if ks == "on" {
            // the guard takes over BEFORE PIA's kill switch is relaxed (V3-03, V3-10)
            self.set_pending(true).map_err(|e| rollback(format!("could not set the guard's block for the hotel login: {e}")))?;
            pia::set_killswitch("auto").map_err(|e| rollback(format!("PIA didn't accept the kill switch change: {e}")))?;
        }
        if state != "Disconnected" {
            pia::disconnect().map_err(|e| rollback(format!("PIA didn't disconnect: {e}")))?;
        }
        let gen = self.policy.lock().unwrap().start_hotel(now, until);
        self.apply_open();
        log(&format!("hotel login #{gen} started ({minutes} min, kill switch was '{ks}')"));
        Ok(format!("hotel login on for {minutes} min - traffic is NOT going through the VPN until it ends"))
    }

    pub fn hotel_stop(self: &Arc<Self>) -> Result<String, String> {
        let _op = self.op_lock()?;
        let ended = self.policy.lock().unwrap().stop_hotel(Instant::now()); // re-armed (N-02)
        self.apply_open(); // protection back first
        if ended.is_none() && outstanding_restore(&self.cfg()).is_none() {
            return Ok("hotel login was not on".into());
        }
        if ended.is_some() {
            log("hotel login ended by hand");
        }
        let gen = ended.unwrap_or_else(|| self.policy.lock().unwrap().hotel_gen());
        self.finish_hotel(gen, ended.is_some())
    }

    /// The timer ran out: finish that login - unless a newer one started in
    /// the meantime (then that one restores when it ends, V3-02).
    fn end_expired_hotel(self: &Arc<Self>, gen: u64) {
        let _op = self.op.lock().unwrap_or_else(|p| p.into_inner());
        if self.stop.load(Ordering::Relaxed) {
            return;
        }
        if let Err(e) = self.finish_hotel(gen, true) {
            log(&format!("after hotel login: {e}"));
        }
    }

    /// The rest of ending hotel login #`gen` - the same for the timer and by
    /// hand, with the `op` lock held and the policy already re-armed and in
    /// "restoring" (nothing opens):
    ///  1. confirm the block is really back in Windows (not just remembered)
    ///  2. put PIA's kill switch back and read it back; only then clear the note
    ///  3. end "restoring"; reconnect the VPN. Safe either way: PIA's kill switch
    ///     is back, or - if it isn't - the guard blocks whenever the VPN is
    ///     down until it is (strict, any mode), retrying every 30 s (N-06).
    fn finish_hotel(self: &Arc<Self>, gen: u64, reconnect: bool) -> Result<String, String> {
        {
            let p = self.policy.lock().unwrap();
            if p.hotel_gen() != gen || p.hotel_active(Instant::now()) {
                log(&format!("hotel login #{gen}: a newer login is running - leaving PIA's kill switch to it"));
                return Ok("a newer hotel login is running - it puts PIA's kill switch back when it ends".into());
            }
        }
        let block = if self.effective_mode() == BlockMode::Off {
            Ok(())
        } else {
            self.apply_open();
            let wants_block = self.policy.lock().unwrap().blocking(Instant::now());
            let open = self.open.lock().unwrap().is_some();
            if !self.armed.load(Ordering::SeqCst) {
                Err("block rules are not in place".to_string())
            } else if wants_block && open {
                Err("the temporary allow-all is still in place".to_string())
            } else {
                let fw = self.fw.lock().unwrap();
                firewall::verify(&fw.expected)
            }
        };
        if let Err(e) = &block {
            log(&format!("after hotel login: block NOT confirmed in the firewall: {e}"));
            self.set_fw_error(e.clone());
        }
        let restored = self.try_restore();
        self.policy.lock().unwrap().restore_done();
        *self.last_probe.lock().unwrap() = None; // fresh look at PIA right away: only that can hand off
        self.apply_open();
        if reconnect {
            log(if restored.is_ok() {
                "reconnecting the VPN"
            } else {
                "reconnecting the VPN (the guard blocks whenever it is down until PIA's kill switch is back)"
            });
            self.spawn_hotel_reconnect(gen);
        }
        let blocked = if self.effective_mode() == BlockMode::Off { "" } else { " - internet blocked until it is connected" };
        match (block, restored) {
            (Err(e), _) => Err(format!("hotel login ended, but the block could not be confirmed in the firewall ({e})")),
            // PIA's kill switch is back, something else isn't (review V4-06)
            (Ok(()), Err(e)) if !self.restore_pending.load(Ordering::Relaxed) => {
                Err(format!("hotel login ended and the VPN is reconnecting, but: {e} - retrying every 30 s"))
            }
            (Ok(()), Err(e)) => Err(format!(
                "hotel login ended and the VPN is reconnecting, but PIA's kill switch isn't back yet ({e}) - the guard blocks whenever the VPN is down until it is; retrying every 30 s"
            )),
            (Ok(()), Ok(())) => Ok(format!("hotel login ended, VPN reconnecting{blocked}")),
        }
    }

    /// Put PIA's kill switch back to what it was before hotel login, verified.
    /// The recovery record and note are only cleared after that worked (audit
    /// P1-05). Ok only when PIA is back, the record is gone AND the guard's
    /// rules are in line again (review V4-06).
    fn try_restore(&self) -> Result<(), String> {
        let Some(saved) = outstanding_restore(&self.cfg()) else {
            return self.set_pending(false).map_err(|e| format!("the guard's firewall rules could not be brought in line ({e})"));
        };
        let ks_back = if saved == "on" { pia::set_killswitch("on") } else { Ok(()) };
        let still_relaxed = ks_back.is_err();
        let r = ks_back.and_then(|_| config::clear_recovery()).and_then(|_| {
            self.update_cfg(|c| {
                c.hotel_active = false;
                c.hotel_saved_killswitch.clear();
            })
        });
        match &r {
            Ok(()) => {
                if self.restore_failing.swap(false, Ordering::Relaxed) || self.restore_pending.load(Ordering::Relaxed) {
                    log("PIA's kill switch setting is back to how it was");
                }
            }
            Err(e) => {
                if !self.restore_failing.swap(true, Ordering::Relaxed) {
                    log(&format!(
                        "could not put PIA's kill switch back yet: {e} - retrying every 30 s; blocking whenever the VPN is down meanwhile"
                    ));
                }
            }
        }
        let synced = self.set_pending(still_relaxed);
        if let Err(e) = &synced {
            log(&format!("block rules not in line after the restore attempt: {e}"));
        }
        match (r, synced) {
            (Err(e), _) => Err(e),
            (Ok(()), Err(e)) => {
                Err(format!("PIA's kill switch is back, but the guard's firewall rules could not be brought in line ({e})"))
            }
            (Ok(()), Ok(())) => Ok(()),
        }
    }

    // ------------------------------------------------------------- commands

    /// Apply first, save after; undo both on failure (review N-14). Making
    /// the block weaker needs an elevated administrator (review N-04). The
    /// mode it already has is only checked, not reinstalled (V3-06).
    pub fn set_mode(&self, mode: BlockMode, admin: bool) -> Result<String, String> {
        let _op = self.op_lock()?;
        let old = self.cfg().mode;
        if mode.weaker_than(old) && !admin {
            return Err(NEEDS_ADMIN.into());
        }
        if mode == old {
            self.enforce(self.effective_mode(), false)?;
            return Ok(format!("block mode already {}", mode.as_str()));
        }
        self.policy.lock().unwrap().set_mode(mode);
        let r = self.enforce(self.effective_mode(), true).and_then(|_| self.update_cfg(|c| c.mode = mode));
        if let Err(e) = r {
            self.policy.lock().unwrap().set_mode(old);
            let back = self.enforce(self.effective_mode(), true);
            log(&format!(
                "block mode NOT changed to {}: {e}{}",
                mode.as_str(),
                if back.is_ok() { format!(" - still {}", old.as_str()) } else { " - and putting the old rules back failed too".into() }
            ));
            return Err(e);
        }
        log(&format!("block mode set to {}", mode.as_str()));
        let mut msg: String = match mode {
            BlockMode::Off => "block off".into(),
            BlockMode::Startup => "blocks at startup/wake until the VPN connects".into(),
            BlockMode::Always => "blocks whenever the VPN is not connected".into(),
        };
        if self.restore_pending.load(Ordering::Relaxed) && mode != BlockMode::Always {
            msg.push_str(" (but blocking whenever the VPN is down until PIA's kill switch is back after the hotel login)");
        }
        Ok(msg)
    }

    /// Choose the encrypted DNS provider (admin). Takes effect at once.
    pub fn set_dns(&self, provider: &str, custom: Option<(&str, &str)>) -> Result<String, String> {
        let ips: Vec<String> =
            custom.map(|(_, ips)| ips.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()).unwrap_or_default();
        let mut want = self.cfg();
        want.set_provider(provider, custom.map(|(url, _)| (url, ips.as_slice())))?; // checked before anything is saved
        let _op = self.op_lock()?;
        self.update_cfg(|c| {
            c.dns_provider = want.dns_provider.clone();
            c.doh_host = want.doh_host.clone();
            c.doh_custom_path = want.doh_custom_path.clone();
            c.doh_bootstrap = want.doh_bootstrap.clone();
        })?;
        self.proxy.set_resolver(resolver_for(&self.cfg()));
        log(&format!("encrypted DNS provider: {provider}"));
        Ok(format!("encrypted DNS provider set to {provider}"))
    }

    pub fn set_profile(&self, id: &str, device: Option<&str>) -> Result<String, String> {
        if !config::valid_profile(id) {
            return Err("that doesn't look like a NextDNS profile ID".into());
        }
        let _op = self.op_lock()?;
        self.update_cfg(|c| {
            c.profile_id = id.to_string();
            if let Some(d) = device {
                c.device_name = d.to_string();
            }
        })?;
        self.proxy.set_resolver(resolver_for(&self.cfg()));
        log("NextDNS profile updated");
        Ok("NextDNS profile saved".into())
    }

    /// Accounts allowed to use the guard without admin rights: Windows SIDs,
    /// or Linux user ids (numbers).
    pub fn set_users(&self, ids: Vec<String>) -> Result<String, String> {
        let ids: Vec<String> = ids.into_iter().filter(|s| !s.is_empty()).collect();
        let numbers: Option<Vec<u32>> = ids.iter().map(|s| s.parse::<u32>().ok()).collect();
        if let Some(uids) = numbers.filter(|_| !ids.is_empty()) {
            let _op = self.op_lock()?;
            self.update_cfg(|c| c.allowed_uids = uids)?;
            return Ok("allowed users saved".into()); // checked per connection: at once
        }
        if ids.iter().any(|s| !config::valid_sid(s)) {
            return Err("invalid account ID".into());
        }
        let _op = self.op_lock()?;
        self.update_cfg(|c| c.allowed_sids = ids)?;
        // the pipe's access list is set when the service starts (V3-11)
        Ok("allowed accounts saved - takes effect when the guard service restarts".into())
    }

    /// Re-read guard.json (after it was edited while the service was stopped).
    pub fn reload(&self) -> Result<String, String> {
        let _op = self.op_lock()?;
        let (cfg, err) = match config::load(|| firewall::installed().unwrap_or(true)) {
            Loaded::Ok(c) | Loaded::Fresh(c) => (c, String::new()),
            Loaded::Recovered(c, why) => (c, why),
        };
        self.proxy.set_resolver(resolver_for(&cfg));
        {
            let mut p = self.policy.lock().unwrap();
            p.set_mode(cfg.mode);
            p.set_connect_at_boot(cfg.connect_at_boot);
        }
        *self.cfg.lock().unwrap() = cfg;
        *self.config_error.lock().unwrap() = err.clone();
        self.sync_rules(true);
        log("settings reloaded");
        if err.is_empty() {
            Ok("reloaded".into())
        } else {
            Err(err)
        }
    }

    pub fn status(&self) -> GuardStatus {
        let now = Instant::now();
        let cfg = self.cfg();
        let (blocking, reason, hotel, hotel_left, pia_state, effective) = {
            let p = self.policy.lock().unwrap();
            (p.blocking(now), p.reason(now), p.hotel_active(now), p.hotel_left(now).as_secs(), p.pia_state(), p.effective())
        };
        // never waits for a firewall install/check (review V4-14)
        let view = self.fw_view.lock().unwrap().clone();
        let armed = self.armed.load(Ordering::SeqCst);
        let open = self.open.lock().unwrap().is_some();
        let settings = self.pia_settings.lock().unwrap().clone();
        let (vpn_adapter, tunnel_watch, route_via_vpn) = {
            use pialite_common::status::tunnel_watch as tw;
            let w = self.tunnel.lock().unwrap();
            let adapter = match (&w.adapter, w.verdict) {
                (Some(a), Tunnel::Down) => format!("{a} (DOWN)"),
                (Some(a), _) => format!("{a} (up)"),
                (None, _) => String::new(),
            };
            let word = if pia_state.as_deref() != Some("Connected") {
                tw::OFF
            } else if w.query_failed {
                tw::QUERY_FAILED
            } else {
                match w.verdict {
                    Tunnel::Unchecked => tw::CHECKING,
                    Tunnel::Up => tw::UP,
                    Tunnel::Down => tw::DOWN,
                    Tunnel::NotFound => tw::NOT_FOUND,
                }
            };
            (adapter, word.to_string(), w.route_ok)
        };
        let network_ready = self.policy.lock().unwrap().network();
        GuardStatus {
            proto: pialite_common::ipc::PROTO,
            version: env!("CARGO_PKG_VERSION").into(),
            mode: cfg.mode,
            armed,
            boot_rules: view.boot_ok,
            boot_rules_error: view.boot_error.clone(),
            // blocking only if the rules are really there
            blocking: blocking && armed && !open,
            reason: if effective != BlockMode::Off && !armed {
                if self.rules_present.load(Ordering::SeqCst) {
                    "protection can NOT be confirmed - block rules could not be checked (see guard.log)".into()
                } else {
                    "block rules NOT in place".into()
                }
            } else {
                reason
            },
            hotel,
            hotel_left,
            hotel_minutes: cfg.hotel_minutes,
            restore_pending: self.restore_pending.load(Ordering::Relaxed) && !hotel,
            pia_state,
            pia_killswitch: settings.as_ref().map(|s| s.killswitch.clone()).unwrap_or_else(|_| "unknown".into()),
            pia_allow_lan: settings.map(|s| s.allow_lan).unwrap_or(false),
            // only NextDNS needs a profile; the other providers are always "set"
            profile_set: cfg.provider() != "nextdns" || !cfg.profile_id.is_empty(),
            dns: self.proxy.stats.snapshot(),
            config_error: self.config_error.lock().unwrap().clone(),
            fw_error: view.error,
            notice: self.notice.lock().unwrap().clone(),
            features: Some({
                let f = cfg.features();
                [("dns", f.dns), ("hotel", f.hotel)].iter().filter(|(_, on)| *on).map(|(n, _)| n.to_string()).collect()
            }),
            dns_provider: if cfg.features().dns { cfg.provider().to_string() } else { String::new() },
            approved_accounts: cfg.allowed_sids.len() as u32,
            vpn_adapter,
            tunnel_watch,
            route_via_vpn,
            // what the guard wants in Windows (review F51-03): the same rule as enforce()
            rules_wanted: Some(effective != BlockMode::Off),
            boot_rules_wanted: Some(effective != BlockMode::Off && cfg.boot_time_rules),
            effective_mode: Some(effective),
            network_ready,
        }
    }

    /// Did a lookup for `name` reach the DNS proxy recently? (test-dns: proves
    /// Windows' own resolver uses the proxy, review N-11)
    pub fn seen(&self, name: &str) -> bool {
        self.proxy.stats.seen(name)
    }

    /// One command from the control pipe. `admin`: the caller is an elevated
    /// administrator. Needed for anything that weakens protection (turning
    /// the block down or off, hotel login) or decides who/what the guard
    /// trusts; the tray asks Windows for "Run as administrator" for those.
    /// Making protection stronger needs no admin (review N-04).
    pub fn handle(self: &Arc<Self>, cmd: &str, admin: bool) -> Result<String, String> {
        let words: Vec<&str> = cmd.split_whitespace().collect();
        let need_admin = || -> Result<(), String> {
            if admin {
                Ok(())
            } else {
                Err(NEEDS_ADMIN.into())
            }
        };
        match words.as_slice() {
            ["ping"] => Ok("pong".into()),
            ["whoami"] => Ok(if admin { "admin" } else { "user" }.into()),
            ["status"] => serde_json::to_string(&self.status()).map_err(|e| e.to_string()),
            ["mode", m] => self.set_mode(BlockMode::parse(m).ok_or("mode must be off, startup or always")?, admin),
            ["unlock"] => need_admin().and_then(|_| self.set_mode(BlockMode::Off, admin)),
            ["hotel", "start"] => need_admin().and_then(|_| self.hotel_start()),
            ["hotel", "stop"] => self.hotel_stop(),
            // from the tray (any user): only makes the guard LESS eager to connect
            ["user", "disconnect"] => {
                self.policy.lock().unwrap().note_user(true);
                log("the user disconnected PIA from the tray - no automatic connect or restart until they connect again");
                Ok("ok".into())
            }
            ["user", "connect"] => {
                self.policy.lock().unwrap().note_user(false);
                Ok("ok".into())
            }
            ["seen", name] => need_admin().map(|_| if self.seen(name) { "yes" } else { "no" }.into()),
            ["set_dns", provider] => need_admin().and_then(|_| self.set_dns(provider, None)),
            ["set_dns", "custom", url, ips] => need_admin().and_then(|_| self.set_dns("custom", Some((url, ips)))),
            ["set_profile", id] => need_admin().and_then(|_| self.set_profile(id, None)),
            ["set_profile", id, dev] => need_admin().and_then(|_| self.set_profile(id, Some(dev))),
            ["set_users", sids] => need_admin().and_then(|_| self.set_users(sids.split(',').map(str::to_string).collect())),
            ["reload"] => need_admin().and_then(|_| self.reload()),
            _ => Err("unknown command".into()),
        }
    }
}

/// The kill switch value a hotel login left to put back, if any: from the
/// recovery record (a damaged record counts - assume "on", the safe value),
/// else from guard.json's note (review V4-03).
fn outstanding_restore(cfg: &Config) -> Option<String> {
    // the same rule the uninstaller applies (review F51-01)
    match config::verdict_for(cfg) {
        config::Verdict::None => None,
        config::Verdict::Restore(s) => Some(s),
        config::Verdict::Unknown(why) => {
            log(&format!("{why} - assuming PIA's kill switch was 'on'"));
            Some("on".into())
        }
    }
}

pub const NEEDS_ADMIN: &str = "needs an administrator (weakens protection - run as administrator)";
pub const BUSY: &str = "busy: another change is still running - try again in a moment";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::tests::{temp_data, ENV_LOCK};
    #[cfg(unix)]
    use crate::config::RecoveryState;
    #[cfg(unix)]
    use std::path::{Path, PathBuf};

    type Hook = Box<dyn FnOnce() + Send>;
    /// Runs once inside apply_open, between its decision and its action.
    static PAUSE: Mutex<Option<Hook>> = Mutex::new(None);
    /// Tests that check one decision at a time stop the guard's own
    /// 1-second tick, so it can't retry or connect between their steps.
    pub static TICK_PAUSED: AtomicBool = AtomicBool::new(false);
    struct NoTick;
    impl NoTick {
        fn new() -> NoTick {
            TICK_PAUSED.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(50)); // a tick already running ends first
            NoTick
        }
    }
    impl Drop for NoTick {
        fn drop(&mut self) {
            TICK_PAUSED.store(false, Ordering::SeqCst);
        }
    }
    /// Runs once right before a worker waits for its turn at PIA commands
    /// (after a restart's first check) - idea taken from the reviewer's patch.
    static BEFORE_PIA_CMD: Mutex<Option<Hook>> = Mutex::new(None);
    pub fn pause_before_pia_cmd() {
        let hook = BEFORE_PIA_CMD.lock().unwrap().take();
        if let Some(h) = hook {
            h();
        }
    }
    /// The next worker signals when it starts waiting for its turn.
    fn signal_when_queued() -> std::sync::mpsc::Receiver<()> {
        let (tx, rx) = std::sync::mpsc::channel();
        *BEFORE_PIA_CMD.lock().unwrap() = Some(Box::new(move || {
            let _ = tx.send(());
        }));
        rx
    }

    pub fn pause_point() {
        let hook = PAUSE.lock().unwrap().take();
        if let Some(h) = hook {
            h();
        }
    }

    fn free_addr() -> SocketAddr {
        let t = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        t.local_addr().unwrap()
    }

    /// A stand-in for PIA: a shell script as piactl plus a settings file it
    /// rewrites, so the hotel paths run for real (review N-17: inject PIA).
    #[cfg(unix)]
    struct FakePia {
        dir: PathBuf,
    }
    #[cfg(unix)]
    impl FakePia {
        fn new(data: &Path) -> FakePia {
            let dir = data.join("fakepia");
            std::fs::create_dir_all(&dir).unwrap();
            let script = r#"#!/bin/sh
D="$(dirname "$0")"
echo "$*" >> "$D/calls"
case "$1" in
  get) cat "$D/state" ;;
  connect) echo Connected > "$D/state" ;;
  disconnect) echo Disconnected > "$D/state" ;;
  -u) if [ -e "$D/fail_set" ]; then echo "refused" >&2; exit 1; fi
      v=$(printf '%s' "$3" | sed 's/.*"killswitch":"\([a-z]*\)".*/\1/')
      printf '{"allowLAN":false,"killswitch":"%s"}' "$v" > "$D/settings.tmp" && mv "$D/settings.tmp" "$D/settings.json" ;;
esac
"#;
            let exe = dir.join("piactl");
            std::fs::write(&exe, script).unwrap();
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::write(dir.join("settings.json"), r#"{"allowLAN":false,"killswitch":"on"}"#).unwrap();
            std::fs::write(dir.join("state"), "Connected\n").unwrap();
            std::env::set_var("PIALITE_PIACTL", &exe);
            std::env::set_var("PIALITE_PIA_SETTINGS", dir.join("settings.json"));
            FakePia { dir }
        }
        fn calls(&self) -> Vec<String> {
            std::fs::read_to_string(self.dir.join("calls")).unwrap_or_default().lines().map(str::to_string).collect()
        }
        fn clear_calls(&self) {
            let _ = std::fs::remove_file(self.dir.join("calls"));
        }
        fn killswitch(&self) -> String {
            pia::read_settings().unwrap().killswitch
        }
        fn fail_set(&self, on: bool) {
            let f = self.dir.join("fail_set");
            if on {
                std::fs::write(f, "").unwrap();
            } else {
                let _ = std::fs::remove_file(f);
            }
        }
        fn wait_call(&self, line: &str) -> bool {
            for _ in 0..100 {
                if self.calls().iter().any(|c| c == line) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(30));
            }
            false
        }
    }
    #[cfg(unix)]
    impl Drop for FakePia {
        fn drop(&mut self) {
            std::env::remove_var("PIALITE_PIACTL");
            std::env::remove_var("PIALITE_PIA_SETTINGS");
        }
    }

    fn saved() -> Config {
        config::load(|| false).config().clone()
    }

    #[test]
    fn modes_status_and_drift_repair() {
        let _g = ENV_LOCK.lock().unwrap();
        let d = temp_data("guard");
        let g = Guard::start_with(free_addr(), false);
        let st = g.status();
        assert_eq!(st.mode, BlockMode::Off);
        assert!(!st.armed && !st.blocking);

        // turning the block on (stronger: no admin needed) while PIA's state is unknown blocks (fail closed)
        g.handle("mode always", false).unwrap();
        let st = g.status();
        assert!(st.armed && st.blocking && st.boot_rules);
        assert_eq!(saved().mode, BlockMode::Always, "saved");

        // PIA connected -> open; disconnected -> blocked again (always mode)
        g.observe(Some("Connected"), Instant::now());
        assert!(!g.status().blocking);
        g.observe(Some("Disconnected"), Instant::now());
        assert!(g.status().blocking);

        // someone flips our block-all into an allow-all under the same key -> put back (N-09)
        // (the background check must not repair it before this test looks - seen on CI)
        let tick = NoTick::new();
        firewall::tamper_action();
        assert!(firewall::verify(&g.fw.lock().unwrap().expected).is_err(), "same key, different action is noticed");
        g.sync_rules(false);
        assert!(firewall::verify(&g.fw.lock().unwrap().expected).is_ok());
        drop(tick);

        // non-admin can't change trusted settings
        assert!(g.handle("set_users S-1-5-21-1-2-3-1001", false).unwrap_err().contains("administrator"));
        assert!(g.handle("set_users S-1-5-21-1-2-3-1001", true).is_ok());
        assert_eq!(g.status().approved_accounts, 1);
        assert!(g.handle("set_users (A;;GA;;;WD)", true).is_err(), "no SDDL injection");
        assert!(g.handle("set_profile abc123", false).is_err());
        assert!(g.handle("seen example.com", false).is_err(), "lookup check is admin-only");
        assert_eq!(g.handle("seen never-asked.pialite.test", true).unwrap(), "no");

        // weakening needs an administrator, strengthening doesn't (review N-04)
        assert_eq!(g.handle("whoami", false).unwrap(), "user");
        assert_eq!(g.handle("whoami", true).unwrap(), "admin");
        for weaker in ["unlock", "mode off", "mode startup", "hotel start"] {
            assert!(g.handle(weaker, false).unwrap_err().contains("administrator"), "{weaker}");
        }
        assert!(g.status().blocking, "still blocking after the refused commands");
        g.handle("mode always", false).unwrap();

        g.handle("unlock", true).unwrap();
        let st = g.status();
        assert!(!st.armed && !st.blocking && !st.boot_rules);
        assert_eq!(firewall::open_count(), 0, "allow-all released with the rules");
        assert!(g.handle("hotel stop", false).unwrap().contains("not on"));
        assert!(g.handle("bogus", false).is_err());
        g.handle("mode startup", false).unwrap();
        g.handle("unlock", true).unwrap();
        g.shutdown();
        let _ = std::fs::remove_dir_all(d);
    }

    /// Records what a restart sends to PIA; can make "PIA" react to the disconnect.
    struct Rec {
        calls: Mutex<Vec<&'static str>>,
        on_disconnect: Mutex<Option<Box<dyn FnOnce() + Send>>>,
        disconnect_fails: bool,
        /// What `state` answers (Err if None).
        state: Mutex<Option<String>>,
        /// Runs inside `state`, before it answers (e.g. a monitor report).
        on_state: Mutex<Option<Box<dyn FnOnce() + Send>>>,
        /// How many `connect` calls fail before they work.
        connect_fails: std::sync::atomic::AtomicUsize,
    }
    impl Rec {
        fn new() -> Arc<Rec> {
            Arc::new(Rec {
                calls: Mutex::new(vec![]),
                on_disconnect: Mutex::new(None),
                disconnect_fails: false,
                state: Mutex::new(None),
                on_state: Mutex::new(None),
                connect_fails: 0.into(),
            })
        }
        /// piactl disconnect fails - and something else makes PIA report Disconnected
        fn failing_disconnect(f: impl FnOnce() + Send + 'static) -> Arc<Rec> {
            Arc::new(Rec {
                calls: Mutex::new(vec![]),
                on_disconnect: Mutex::new(Some(Box::new(f))),
                disconnect_fails: true,
                state: Mutex::new(None),
                on_state: Mutex::new(None),
                connect_fails: 0.into(),
            })
        }
        fn reacting(f: impl FnOnce() + Send + 'static) -> Arc<Rec> {
            let r = Rec::new();
            *r.on_disconnect.lock().unwrap() = Some(Box::new(f));
            r
        }
        fn calls(&self) -> Vec<&'static str> {
            self.calls.lock().unwrap().clone()
        }
    }
    impl PiaOps for Rec {
        fn disconnect(&self) -> Result<String, String> {
            self.calls.lock().unwrap().push("disconnect");
            let f = self.on_disconnect.lock().unwrap().take();
            if let Some(f) = f {
                f();
            }
            if self.disconnect_fails {
                return Err("piactl disconnect: timed out".into());
            }
            Ok(String::new())
        }
        fn connect(&self) -> Result<String, String> {
            self.calls.lock().unwrap().push("connect");
            let fails = &self.connect_fails;
            if fails.load(Ordering::SeqCst) > 0 {
                fails.fetch_sub(1, Ordering::SeqCst);
                return Err("piactl connect: timed out".into());
            }
            Ok(String::new())
        }
        fn state(&self) -> Result<String, String> {
            self.calls.lock().unwrap().push("state");
            let f = self.on_state.lock().unwrap().take();
            if let Some(f) = f {
                f();
            }
            self.state.lock().unwrap().clone().ok_or_else(|| "PIA not answering".to_string())
        }
    }

    /// Review V60-01: a restart decided for a stuck attempt must not touch a
    /// connection that succeeded meanwhile, override a user's disconnect, act
    /// on a newer attempt, or run when the block no longer waits for the VPN;
    /// it never connects without PIA reporting Disconnected first; one at a time.
    #[test]
    fn a_queued_restart_only_acts_on_the_same_stuck_attempt() {
        let _g = ENV_LOCK.lock().unwrap();
        let d = temp_data("kick");
        let g = Guard::start_with(free_addr(), false);
        g.handle("mode always", false).unwrap();
        let attempt = |g: &Arc<Guard>| {
            g.observe(Some("Connecting"), Instant::now());
            g.policy.lock().unwrap().attempt_gen()
        };
        // 1. PIA connects before the worker runs: nothing is sent
        let gen = attempt(&g);
        g.observe(Some("Connected"), Instant::now());
        let r = Rec::new();
        assert_eq!(g.run_restart(gen, "test", r.as_ref()), Restart::NotNeeded);
        assert!(r.calls().is_empty(), "a healthy new connection is left alone");
        // 2. the user disconnects before it runs: no reconnect against them
        g.observe(Some("Disconnected"), Instant::now());
        let gen = attempt(&g);
        g.observe(Some("Disconnected"), Instant::now());
        assert_eq!(g.run_restart(gen, "test", r.as_ref()), Restart::NotNeeded);
        // 3. a newer attempt than the one it was decided for
        let old = attempt(&g);
        g.observe(Some("Disconnected"), Instant::now());
        let gen = attempt(&g);
        assert!(gen > old);
        assert_eq!(g.run_restart(old, "test", r.as_ref()), Restart::NotNeeded);
        // 4. block turned off meanwhile
        g.handle("mode off", true).unwrap();
        assert_eq!(g.run_restart(gen, "test", r.as_ref()), Restart::NotNeeded);
        g.handle("mode always", false).unwrap();
        // 5. a hotel login meanwhile
        let now = Instant::now();
        g.policy.lock().unwrap().start_hotel(now, now + Duration::from_secs(60));
        assert_eq!(g.run_restart(gen, "test", r.as_ref()), Restart::NotNeeded);
        g.policy.lock().unwrap().stop_hotel(Instant::now());
        g.policy.lock().unwrap().restore_done();
        assert!(r.calls().is_empty(), "nothing sent in 1-5");
        // 6. the normal case: disconnect, PIA REPORTS Disconnected, connect
        let gen = attempt(&g);
        let g2 = g.clone();
        let r = Rec::reacting(move || g2.observe(Some("Disconnected"), Instant::now()));
        assert_eq!(g.run_restart(gen, "test", r.as_ref()), Restart::Done);
        assert_eq!(r.calls(), ["disconnect", "connect"]);
        // 7. PIA stays "Disconnecting": no blind connect after the wait
        let gen = attempt(&g);
        let g2 = g.clone();
        let r = Rec::reacting(move || g2.observe(Some("Disconnecting"), Instant::now()));
        assert_eq!(g.run_restart(gen, "test", r.as_ref()), Restart::NoDisconnect);
        assert_eq!(r.calls(), ["disconnect"]);
        // 8. PIA (or the user) connects again during the wait: no second connect
        let gen = attempt(&g);
        let g2 = g.clone();
        let r = Rec::reacting(move || g2.observe(Some("Connected"), Instant::now()));
        assert_eq!(g.run_restart(gen, "test", r.as_ref()), Restart::LeftAlone);
        assert_eq!(r.calls(), ["disconnect"]);
        // 9. one worker at a time
        let gen = attempt(&g);
        g.kick_running.store(true, Ordering::SeqCst);
        let r = Rec::new();
        g.restart_attempt(gen, "test", r.clone());
        std::thread::sleep(Duration::from_millis(200));
        assert!(r.calls().is_empty(), "a second restart while one runs is dropped");
        g.kick_running.store(false, Ordering::SeqCst);
        // 10. (FINAL-02) disconnect fails, then PIA reports Disconnected anyway
        //     (the user, or something else): no connect
        let gen = attempt(&g);
        let g2 = g.clone();
        let r = Rec::failing_disconnect(move || g2.observe(Some("Disconnected"), Instant::now()));
        assert_eq!(g.run_restart(gen, "test", r.as_ref()), Restart::DisconnectFailed);
        assert_eq!(r.calls(), ["disconnect"]);
        // 11. the user presses Disconnect in the tray while the restart waits
        let gen = attempt(&g);
        let g2 = g.clone();
        let r = Rec::reacting(move || {
            g2.handle("user disconnect", false).unwrap();
            g2.observe(Some("Disconnected"), Instant::now());
        });
        assert_eq!(g.run_restart(gen, "test", r.as_ref()), Restart::NotNeeded);
        assert_eq!(r.calls(), ["disconnect"], "the user's choice stands");
        g.handle("user connect", false).unwrap();
        // 12. someone else started a new attempt (and it failed again) while the
        //     restart waited: the last check before connecting sees the newer
        //     attempt -> no connect
        let gen = attempt(&g);
        let g2 = g.clone();
        let r = Rec::reacting(move || {
            g2.observe(Some("Disconnected"), Instant::now());
            g2.observe(Some("Connecting"), Instant::now()); // someone else started a new attempt
            g2.observe(Some("Disconnected"), Instant::now());
        });
        assert_eq!(g.run_restart(gen, "test", r.as_ref()), Restart::NotNeeded);
        assert_eq!(r.calls(), ["disconnect"]);
        g.handle("unlock", true).unwrap();
        g.shutdown();
        let _ = std::fs::remove_dir_all(d);
    }

    /// Review V63-01: a restart queued behind another PIA command checks again
    /// when it gets its turn - nothing is sent if, while it waited, PIA
    /// connected, a newer attempt started, the block went off, a hotel login
    /// started, or the user pressed Disconnect.
    #[test]
    fn a_restart_waiting_its_turn_checks_again() {
        let _g = ENV_LOCK.lock().unwrap();
        let d = temp_data("kickqueue");
        let g = Guard::start_with(free_addr(), false);
        g.handle("mode always", false).unwrap();
        type Change = Box<dyn Fn(&Arc<Guard>)>;
        let cases: Vec<(&str, Change)> = vec![
            ("PIA connected", Box::new(|g| g.observe(Some("Connected"), Instant::now()))),
            (
                "a newer attempt",
                Box::new(|g| {
                    g.observe(Some("Disconnected"), Instant::now());
                    g.observe(Some("Connecting"), Instant::now());
                }),
            ),
            ("block turned off", Box::new(|g| drop(g.handle("mode off", true).unwrap()))),
            (
                "hotel login",
                Box::new(|g| {
                    let now = Instant::now();
                    g.policy.lock().unwrap().start_hotel(now, now + Duration::from_secs(60));
                }),
            ),
            ("Disconnect pressed", Box::new(|g| drop(g.handle("user disconnect", false).unwrap()))),
        ];
        for (name, change) in cases {
            g.observe(Some("Disconnected"), Instant::now());
            g.observe(Some("Connecting"), Instant::now());
            let gen = g.policy.lock().unwrap().attempt_gen();
            let r = Rec::new();
            let held = g.pia_cmd.lock().unwrap(); // another PIA command is running
            let queued = signal_when_queued();
            let (g2, r2) = (g.clone(), r.clone());
            let worker = std::thread::spawn(move || g2.run_restart(gen, "test", r2.as_ref()));
            queued.recv_timeout(Duration::from_secs(5)).expect("passed its first check, now waits for its turn");
            change(&g);
            drop(held);
            assert_eq!(worker.join().unwrap(), Restart::NotNeeded, "{name}");
            assert!(r.calls().is_empty(), "{name}: nothing sent");
            // back to the starting point
            let mut p = g.policy.lock().unwrap();
            p.stop_hotel(Instant::now());
            p.restore_done();
            p.note_user(false);
            drop(p);
            g.handle("mode always", false).unwrap();
        }
        // control: nothing changed while it waited -> it does restart
        g.observe(Some("Connecting"), Instant::now());
        let gen = g.policy.lock().unwrap().attempt_gen();
        let g3 = g.clone();
        let r = Rec::reacting(move || g3.observe(Some("Disconnected"), Instant::now()));
        let held = g.pia_cmd.lock().unwrap();
        let queued = signal_when_queued();
        let (g2, r2) = (g.clone(), r.clone());
        let worker = std::thread::spawn(move || g2.run_restart(gen, "test", r2.as_ref()));
        queued.recv_timeout(Duration::from_secs(5)).unwrap();
        drop(held);
        assert_eq!(worker.join().unwrap(), Restart::Done);
        assert_eq!(r.calls(), ["disconnect", "connect"]);
        g.handle("unlock", true).unwrap();
        g.shutdown();
        let _ = std::fs::remove_dir_all(d);
    }

    /// Review V63-04: the reconnect after a hotel login waits its turn behind
    /// other PIA commands and then checks again: it doesn't connect when PIA
    /// connected meanwhile or the user pressed Disconnect - and otherwise does.
    #[cfg(unix)] // the fake piactl is a shell script
    #[test]
    fn hotel_reconnect_waits_its_turn_and_checks_again() {
        let _g = ENV_LOCK.lock().unwrap();
        let d = temp_data("hotelqueue");
        let pia = FakePia::new(&d);
        let g = Guard::start_with(free_addr(), false);
        g.handle("mode startup", false).unwrap();
        g.observe(Some("Connected"), Instant::now());
        type Change = Box<dyn Fn(&Arc<Guard>)>;
        let cases: Vec<(&str, Change, bool)> = vec![
            ("PIA connected meanwhile", Box::new(|g| g.observe(Some("Connected"), Instant::now())), false),
            ("Disconnect pressed meanwhile", Box::new(|g| drop(g.handle("user disconnect", false).unwrap())), false),
            ("nothing changed", Box::new(|_| {}), true),
        ];
        for (name, change, connects) in cases {
            g.handle("hotel start", true).unwrap();
            g.observe(Some("Disconnected"), Instant::now());
            pia.clear_calls();
            let held = g.pia_cmd.lock().unwrap(); // e.g. a restart in progress
            let queued = signal_when_queued();
            g.handle("hotel stop", false).unwrap();
            queued.recv_timeout(Duration::from_secs(5)).expect("the reconnect waits for its turn");
            std::thread::sleep(Duration::from_millis(100));
            assert!(!pia.calls().iter().any(|c| c == "connect"), "{name}: not while another command runs");
            change(&g);
            drop(held);
            std::thread::sleep(Duration::from_millis(400));
            assert_eq!(pia.calls().iter().any(|c| c == "connect"), connects, "{name}: {:?}", pia.calls());
            g.handle("user connect", false).unwrap();
            g.observe(Some("Connected"), Instant::now());
        }
        g.handle("unlock", true).unwrap();
        g.shutdown();
        let _ = std::fs::remove_dir_all(d);
    }

    /// Review V64-02: the reconnect after a hotel login doesn't trust a
    /// report from BEFORE the login ended ("Connected" before the hotel
    /// login, the monitor not having reported the hotel disconnect yet): it
    /// asks PIA - and still doesn't connect twice when PIA really is
    /// connected again after the login.
    #[test]
    fn hotel_return_does_not_trust_a_report_from_before_it_ended() {
        let _g = ENV_LOCK.lock().unwrap();
        let _quiet = NoTick::new();
        let d = temp_data("hotelstale");
        let g = Guard::start_with(free_addr(), false);
        let ended_hotel = |g: &Arc<Guard>| {
            let mut p = g.policy.lock().unwrap();
            let now = Instant::now();
            let gen = p.start_hotel(now, now + Duration::from_secs(180));
            p.stop_hotel(Instant::now()); // ends and re-arms; nothing reported since
            p.restore_done();
            gen
        };
        // 1. last report: "Connected" from before the login; PIA (asked) says Disconnected -> connect
        g.observe(Some("Connected"), Instant::now());
        std::thread::sleep(Duration::from_millis(5));
        let gen = ended_hotel(&g);
        let r = Rec::new();
        *r.state.lock().unwrap() = Some("Disconnected".into());
        assert_eq!(g.run_hotel_reconnect(gen, r.as_ref(), &[]), HotelReturn::Sent, "a pre-login 'Connected' must not stop the reconnect");
        assert_eq!(r.calls(), ["state", "connect"], "asked PIA first, then connected");
        // 2. same, but PIA can't be asked: connect anyway (harmless if it is connected)
        g.observe(Some("Connected"), Instant::now());
        std::thread::sleep(Duration::from_millis(5));
        let gen = ended_hotel(&g);
        let r = Rec::new();
        assert_eq!(g.run_hotel_reconnect(gen, r.as_ref(), &[]), HotelReturn::Sent);
        assert_eq!(r.calls(), ["state", "connect"]);
        // 3. a report AFTER the login ended says Connected: no second connect, PIA not even asked
        let gen = ended_hotel(&g);
        g.observe(Some("Connected"), Instant::now());
        let r = Rec::new();
        assert_eq!(g.run_hotel_reconnect(gen, r.as_ref(), &[]), HotelReturn::NotNeeded);
        assert!(r.calls().is_empty());
        // V65-01: while PIA is being asked, the monitor reports something newer -
        // the NEWER report decides, not PIA's (older) answer
        // (A) newer Connecting, PIA's answer Disconnected -> no connect
        let gen = ended_hotel(&g);
        let r = Rec::new();
        *r.state.lock().unwrap() = Some("Disconnected".into());
        let g2 = g.clone();
        // (the report comes while PIA is being asked: newer than the moment of asking)
        *r.on_state.lock().unwrap() = Some(Box::new(move || {
            std::thread::sleep(Duration::from_millis(2));
            g2.observe(Some("Connecting"), Instant::now())
        }));
        assert_eq!(g.run_hotel_reconnect(gen, r.as_ref(), &[]), HotelReturn::NotNeeded, "newer Connecting wins");
        assert_eq!(r.calls(), ["state"]);
        // (B) newer Disconnected, PIA's answer Connected -> connect
        let gen = ended_hotel(&g);
        let r = Rec::new();
        *r.state.lock().unwrap() = Some("Connected".into());
        let g2 = g.clone();
        *r.on_state.lock().unwrap() = Some(Box::new(move || {
            std::thread::sleep(Duration::from_millis(2));
            g2.observe(Some("Disconnected"), Instant::now())
        }));
        assert_eq!(g.run_hotel_reconnect(gen, r.as_ref(), &[]), HotelReturn::Sent, "newer Disconnected wins");
        assert_eq!(r.calls(), ["state", "connect"]);
        g.shutdown();
        let _ = std::fs::remove_dir_all(d);
    }

    /// Review V65-02: a failed reconnect after a hotel login is tried again
    /// (checking everything again each time - a failed command may still have
    /// worked); if every try fails, the status tells the user to press
    /// Connect; and a retry never goes against a newer login or a Disconnect.
    #[test]
    fn hotel_return_retries_a_failed_connect_and_says_so() {
        let _g = ENV_LOCK.lock().unwrap();
        let _quiet = NoTick::new();
        let d = temp_data("hotelretry");
        let g = Guard::start_with(free_addr(), false);
        let ended_hotel = |g: &Arc<Guard>| {
            let mut p = g.policy.lock().unwrap();
            let now = Instant::now();
            let gen = p.start_hotel(now, now + Duration::from_secs(180));
            p.stop_hotel(Instant::now());
            p.restore_done();
            drop(p);
            g.observe(Some("Disconnected"), Instant::now());
            gen
        };
        let retry = [Duration::from_millis(20), Duration::from_millis(20)];
        // fails once, then works
        let gen = ended_hotel(&g);
        let r = Rec::new();
        r.connect_fails.store(1, Ordering::SeqCst);
        assert_eq!(g.run_hotel_reconnect(gen, r.as_ref(), &retry), HotelReturn::Sent);
        assert_eq!(r.calls(), ["connect", "connect"]);
        assert!(g.status().notice.is_empty());
        // fails every time: the user is told
        let gen = ended_hotel(&g);
        let r = Rec::new();
        r.connect_fails.store(9, Ordering::SeqCst);
        assert!(matches!(g.run_hotel_reconnect(gen, r.as_ref(), &retry), HotelReturn::Failed(_)));
        assert_eq!(r.calls(), ["connect", "connect", "connect"], "bounded: three tries");
        assert!(g.status().notice.contains("press Connect"), "{}", g.status().notice);
        g.observe(Some("Connecting"), Instant::now());
        g.observe(Some("Connected"), Instant::now());
        assert!(g.status().notice.is_empty(), "connected: the notice goes away");
        // the failed command worked after all (PIA connecting): no blind retry
        let gen = ended_hotel(&g);
        let g2 = g.clone();
        let r = Rec::new();
        r.connect_fails.store(9, Ordering::SeqCst);
        let calls_before_retry = {
            let g3 = g2.clone();
            move || g3.observe(Some("Connecting"), Instant::now())
        };
        // after the first (failed) try PIA reports Connecting
        let t = std::thread::spawn({
            let r = r.clone();
            move || {
                while r.calls().is_empty() {
                    std::thread::sleep(Duration::from_millis(1));
                }
                calls_before_retry();
            }
        });
        let res = g.run_hotel_reconnect(gen, r.as_ref(), &[Duration::from_millis(150)]);
        t.join().unwrap();
        assert_eq!(res, HotelReturn::NotNeeded, "PIA connecting after all: not sent again");
        assert_eq!(r.calls(), ["connect"]);
        // a Disconnect pressed between tries stops the retries
        let gen = ended_hotel(&g);
        let r = Rec::new();
        r.connect_fails.store(9, Ordering::SeqCst);
        let t = std::thread::spawn({
            let (r, g) = (r.clone(), g.clone());
            move || {
                while r.calls().is_empty() {
                    std::thread::sleep(Duration::from_millis(1));
                }
                g.handle("user disconnect", false).unwrap();
            }
        });
        assert_eq!(g.run_hotel_reconnect(gen, r.as_ref(), &[Duration::from_millis(150)]), HotelReturn::NotNeeded);
        t.join().unwrap();
        assert_eq!(r.calls(), ["connect"]);
        g.shutdown();
        let _ = std::fs::remove_dir_all(d);
    }

    /// Review V64-04: hotel entry takes its turn at PIA commands - it never
    /// changes PIA's kill switch or connection while a reconnect is running,
    /// and if the turn doesn't come within the bound it says "busy" having
    /// changed nothing.
    #[cfg(unix)] // the fake piactl is a shell script
    #[test]
    fn hotel_entry_waits_its_turn_at_pia_commands() {
        let _g = ENV_LOCK.lock().unwrap();
        let _quiet = NoTick::new();
        let d = temp_data("hotelentry");
        let pia = FakePia::new(&d);
        let g = Guard::start_with(free_addr(), false);
        g.handle("mode startup", false).unwrap();
        g.observe(Some("Connected"), Instant::now());
        // a) the turn comes: nothing touched while it waits, then the full entry
        pia.clear_calls();
        let held = g.pia_cmd.lock().unwrap(); // e.g. the startup connect is running
        let queued = signal_when_queued();
        let g2 = g.clone();
        let entry = std::thread::spawn(move || g2.handle("hotel start", true));
        queued.recv_timeout(Duration::from_secs(5)).expect("hotel entry waits for its turn");
        std::thread::sleep(Duration::from_millis(200));
        assert!(pia.calls().is_empty(), "nothing sent to PIA while another command runs: {:?}", pia.calls());
        assert!(!saved().hotel_active, "nothing written either");
        drop(held);
        entry.join().unwrap().unwrap();
        assert!(pia.calls().iter().any(|c| c == "disconnect") && g.status().hotel);
        g.handle("hotel stop", false).unwrap();
        assert!(pia.wait_call("connect"));
        g.observe(Some("Connected"), Instant::now());
        // b) the turn doesn't come in time: "busy", nothing changed
        pia.clear_calls();
        let held = g.pia_cmd.lock().unwrap();
        let e = g.handle("hotel start", true).unwrap_err();
        assert!(e.contains("busy"), "{e}");
        drop(held);
        assert!(pia.calls().is_empty() && !g.status().hotel && !saved().hotel_active);
        g.handle("unlock", true).unwrap();
        g.shutdown();
        let _ = std::fs::remove_dir_all(d);
    }

    /// The v0.6.0 lock-out: a new guard starts, refreshing the rules fails,
    /// the previous rules are still in Windows (and block) - PIA connecting
    /// must still let traffic through, and the problem must be visible.
    #[test]
    fn a_failed_rule_refresh_never_strands_the_vpn() {
        // v0.6.0 lock-out + review FINAL-01: after a failed refresh only
        // VERIFIED rules count as protection, but whenever PIA Lite rules are
        // (or may be) in Windows the VPN-connected allow-all is still added.
        use firewall::{Cond, FilterSpec, Kind};
        let _g = ENV_LOCK.lock().unwrap();
        let _quiet = NoTick::new();
        let d = temp_data("refreshfail");
        let g = Guard::start_with(free_addr(), false);
        g.handle("mode startup", false).unwrap();
        let (good, boot) = firewall::rules();
        assert!(!good.is_empty() && !boot.is_empty());

        // (a) the plan changes (Allow LAN on) and the refresh fails: the set the
        //     guard last verified is still there exactly -> verified, kept
        crate::pia::set_test_allow_lan(Some(true));
        firewall::fail_next_install();
        g.sync_rules(false);
        let st = g.status();
        assert!(st.armed && st.blocking && st.fw_error.contains("last verified"), "(a) {st:?}");
        crate::pia::set_test_allow_lan(None);
        g.shutdown();
        drop(g);

        let block_all = |v6| FilterSpec { index: 0, kind: Kind::Persistent, v6, permit: false, weight: 0, cond: Cond::All };
        let lan_variant = firewall::specs(&firewall::plan(&crate::pia::engine_exes(), true), Kind::Persistent);
        let mut flipped = good.clone();
        for f in flipped.iter_mut().filter(|f| f.cond == Cond::All && !f.v6) {
            f.permit = true; // the IPv4 block-everything turned into allow-everything
        }
        let mut extra = good.clone();
        extra.push(FilterSpec {
            index: extra.len() as u32,
            kind: Kind::Persistent,
            v6: false,
            permit: true,
            weight: 14,
            cond: Cond::RemotePort(443),
        });
        // (name, persistent rules, boot rules, inspect fails, verified?, present?)
        type Case = (&'static str, Vec<FilterSpec>, Vec<FilterSpec>, bool, bool, bool);
        let cases: Vec<Case> = vec![
            ("(g) the full planned set is still there (rolled back)", good.clone(), boot.clone(), false, true, true),
            ("older rules for the other Allow LAN choice", lan_variant.clone(), boot.clone(), false, true, true),
            ("(b) one boot-time rule only", vec![], vec![boot[0].clone()], false, false, true),
            ("(c) only the IPv4 block-everything", vec![block_all(false)], vec![], false, false, true),
            ("(d) block-everything turned into a permit", flipped, boot.clone(), false, false, true),
            ("(e) an unrecognised rule under PIA Lite's name", extra, boot.clone(), false, false, true),
            ("(f) Windows can't be asked", lan_variant.clone(), boot.clone(), true, false, true),
            ("(V63-05) older rules + a temporary permit the guard didn't add", lan_variant, boot.clone(), false, false, true),
            ("nothing in Windows", vec![], vec![], false, false, false),
        ];
        for (name, persistent, boot_rules, inspect_fails, verified, present) in cases {
            firewall::set_rules(persistent, boot_rules);
            firewall::fail_inspect(inspect_fails);
            firewall::set_stray_permit(name.starts_with("(V63-05)"));
            firewall::fail_installs(usize::MAX); // the guard's own retries (its 1-s tick) fail too
            let g = Guard::start_with(free_addr(), false);
            let st = g.status();
            assert_eq!(st.armed, verified, "{name}: {st:?}");
            assert!(!st.fw_error.is_empty(), "{name}: the failure is shown");
            assert_eq!(st.blocking, verified, "{name}: 'blocking' only claimed when verified");
            if present && !verified {
                assert!(st.reason.contains("can NOT be confirmed"), "{name}: {}", st.reason);
            }
            // PIA connects (straight into the state machine: no adapter look,
            // nothing else that could retry the rules in between)
            let _ = g.policy.lock().unwrap().observe(Some("Connected"), Instant::now());
            g.apply_open();
            assert_eq!(firewall::open_count(), usize::from(present), "{name}: VPN connected -> opened only if rules are there");
            firewall::fail_inspect(false);
            firewall::set_stray_permit(false);
            firewall::fail_installs(0);
            g.shutdown();
            drop(g);
            assert_eq!(firewall::open_count(), 0);
        }
        firewall::set_rules(vec![], vec![]);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn mode_change_applies_before_saving_and_reverts_on_failure() {
        // review N-14
        let _g = ENV_LOCK.lock().unwrap();
        let d = temp_data("modefail");
        let g = Guard::start_with(free_addr(), false);
        firewall::fail_next_install();
        assert!(g.handle("mode always", false).is_err());
        let st = g.status();
        assert!(st.mode == BlockMode::Off && !st.armed && !st.blocking, "nothing half-done");
        assert_eq!(saved().mode, BlockMode::Off, "a mode that couldn't be applied isn't saved");

        g.handle("mode always", false).unwrap();
        // saving fails -> Windows goes back to the old rules too
        let p = d.join("guard.json");
        std::fs::remove_file(&p).unwrap();
        std::fs::create_dir(&p).unwrap();
        assert!(g.handle("mode off", true).is_err());
        let st = g.status();
        assert!(st.mode == BlockMode::Always && st.armed && st.blocking, "still protected as before");
        std::fs::remove_dir(&p).unwrap();
        g.handle("unlock", true).unwrap();
        assert_eq!(saved().mode, BlockMode::Off);
        g.shutdown();
        let _ = std::fs::remove_dir_all(d);
    }

    /// 0.9: with encrypted DNS turned off nothing listens on port 53, and
    /// with hotel login turned off it can't be started; the status says
    /// which features run.
    #[test]
    fn optional_features_are_honoured() {
        let _g = ENV_LOCK.lock().unwrap();
        let d = temp_data("features");
        let c = Config { features: Some(config::Features { dns: false, hotel: false }), ..Default::default() };
        config::save(&c).unwrap();
        let addr = free_addr();
        let g = Guard::start_with(addr, false);
        std::thread::sleep(Duration::from_millis(300));
        let st = g.status();
        assert!(!st.dns.listening && st.dns.bind_error.contains("turned off"), "{:?}", st.dns);
        assert!(std::net::UdpSocket::bind(addr).is_ok(), "port 53 (test port) left free");
        assert_eq!(st.features, Some(vec![]));
        assert_eq!(st.dns_provider, "");
        let e = g.handle("hotel start", true).unwrap_err();
        assert!(e.contains("turned off"), "{e}");
        assert!(!g.status().hotel);
        g.shutdown();
        drop(g);
        // DNS on with Quad9, hotel on
        let mut c = Config { features: Some(config::Features { dns: true, hotel: true }), ..Default::default() };
        c.set_provider("quad9", None).unwrap();
        config::save(&c).unwrap();
        let g = Guard::start_with(free_addr(), false);
        let st = g.status();
        assert_eq!(st.features, Some(vec!["dns".to_string(), "hotel".to_string()]));
        assert_eq!(st.dns_provider, "quad9");
        // provider change: admin only, checked before saving
        assert!(g.handle("set_dns cloudflare", false).is_err());
        assert!(g.handle("set_dns nonsense", true).is_err());
        assert_eq!(saved().dns_provider, "quad9", "a bad choice changes nothing");
        g.handle("set_dns cloudflare", true).unwrap();
        assert_eq!((saved().dns_provider.as_str(), saved().doh_host.as_str()), ("cloudflare", "cloudflare-dns.com"));
        g.handle("set_dns custom https://doh.example.net/dns-query 203.0.113.7,203.0.113.8", true).unwrap();
        assert_eq!(saved().doh_bootstrap, vec!["203.0.113.7", "203.0.113.8"]);
        g.shutdown();
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(unix)] // the fake piactl is a shell script
    #[test]
    fn hotel_exit_reblocks_restores_then_reconnects() {
        // review N-02 / N-06, manual stop and timer, restore OK and failing
        let _g = ENV_LOCK.lock().unwrap();
        let d = temp_data("hotelcycle");
        let pia = FakePia::new(&d);
        let g = Guard::start_with(free_addr(), false);
        g.handle("mode startup", false).unwrap();
        g.observe(Some("Connected"), Instant::now());
        assert!(!g.status().blocking, "handed off to PIA");

        g.handle("hotel start", true).unwrap();
        assert_eq!(pia.killswitch(), "auto");
        assert!(pia.calls().iter().any(|c| c == "disconnect"));
        assert!(saved().hotel_active, "recovery note written before PIA was touched");
        g.observe(Some("Disconnected"), Instant::now());
        let st = g.status();
        assert!(st.hotel && !st.blocking);

        // --- stopped by hand, restore works
        pia.clear_calls();
        g.handle("hotel stop", false).unwrap();
        let st = g.status();
        assert!(st.blocking && !st.hotel, "startup mode blocks again right away (N-02)");
        assert_eq!(firewall::open_count(), 0, "allow-all gone");
        assert_eq!(pia.killswitch(), "on", "PIA's kill switch back, read back");
        assert!(!saved().hotel_active, "note cleared only after that");
        assert!(pia.wait_call("connect"), "then the VPN is reconnected");
        let calls = pia.calls();
        let restore = calls.iter().position(|c| c.contains("applysettings")).unwrap();
        let connect = calls.iter().position(|c| c == "connect").unwrap();
        assert!(restore < connect, "kill switch restored before reconnecting: {calls:?}");
        g.observe(Some("Connected"), Instant::now());
        assert!(!g.status().blocking);

        // --- stopped by hand, restore FAILS
        g.handle("hotel start", true).unwrap();
        g.observe(Some("Disconnected"), Instant::now());
        pia.fail_set(true);
        let e = g.handle("hotel stop", false).unwrap_err();
        assert!(e.contains("isn't back yet"), "{e}");
        let st = g.status();
        assert!(st.blocking && st.restore_pending, "blocked, warning shown");
        assert!(saved().hotel_active, "note kept until the restore works");
        assert!(g.status().reason.contains("isn't back"), "{}", g.status().reason);
        // VPN back -> open; VPN drops -> the guard blocks, even in startup mode (N-06)
        g.observe(Some("Connected"), Instant::now());
        assert!(!g.status().blocking);
        g.observe(Some("Disconnected"), Instant::now());
        assert!(g.status().blocking, "PIA's kill switch isn't back, so the guard blocks");
        // restore works on a later retry -> normal startup-mode hand-off again
        pia.fail_set(false);
        assert!(g.try_restore().is_ok());
        assert!(!g.status().restore_pending && !saved().hotel_active);
        assert_eq!(pia.killswitch(), "on");
        g.observe(Some("Connected"), Instant::now());
        g.observe(Some("Disconnected"), Instant::now());
        assert!(!g.status().blocking, "PIA's own kill switch is in charge after the hand-off again");

        // --- the timer runs out
        g.observe(Some("Connected"), Instant::now());
        g.handle("hotel start", true).unwrap();
        g.observe(Some("Disconnected"), Instant::now());
        pia.clear_calls();
        let now = Instant::now();
        g.policy.lock().unwrap().start_hotel(now, now); // time is up
        g.tick();
        assert!(g.status().blocking, "blocked the moment the timer ran out (N-02)");
        assert!(pia.wait_call("connect"));
        assert_eq!(pia.killswitch(), "on");
        assert!(!saved().hotel_active);

        g.handle("unlock", true).unwrap();
        g.shutdown();
        drop(pia);
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(unix)] // the fake piactl is a shell script
    #[test]
    fn late_timer_never_ends_a_newer_hotel_login() {
        // review V3-02: the timer's worker of login #1 runs only after login #2 started
        let _g = ENV_LOCK.lock().unwrap();
        let d = temp_data("hotelgen");
        let pia = FakePia::new(&d);
        let g = Guard::start_with(free_addr(), false);
        g.handle("mode always", false).unwrap();
        g.observe(Some("Connected"), Instant::now());
        g.handle("hotel start", true).unwrap();
        assert_eq!(pia.killswitch(), "auto");
        // time is up for #1; its worker hasn't got the lock yet
        let first = g.policy.lock().unwrap().stop_hotel(Instant::now()).unwrap();
        g.apply_open();
        // a new login starts first: it undoes #1's change before saving its own note
        g.handle("hotel start", true).unwrap();
        let cfg = saved();
        assert!(cfg.hotel_active && cfg.hotel_saved_killswitch == "on", "the user's 'on' is not overwritten with 'auto'");
        assert_eq!(pia.killswitch(), "auto");
        pia.clear_calls();
        // now the late worker of #1 runs
        g.end_expired_hotel(first);
        std::thread::sleep(Duration::from_millis(300));
        let st = g.status();
        assert!(st.hotel && !st.blocking, "login #2 still on");
        assert_eq!(pia.killswitch(), "auto", "#2's kill switch change untouched");
        assert!(saved().hotel_active, "#2's note kept");
        assert!(!pia.calls().iter().any(|c| c == "connect" || c.contains("applysettings")), "{:?}", pia.calls());
        // #2 ends normally -> the user's original setting comes back
        g.handle("hotel stop", false).unwrap();
        assert_eq!(pia.killswitch(), "on");
        assert!(!saved().hotel_active);
        g.handle("unlock", true).unwrap();
        g.shutdown();
        drop(pia);
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(unix)] // the fake piactl is a shell script
    #[test]
    fn nothing_opens_during_restore_and_off_mode_blocks_until_restored() {
        // review V3-03 (Connected arrives mid-restore) and V3-10 (block off,
        // PIA's kill switch on, restore fails)
        let _g = ENV_LOCK.lock().unwrap();
        let d = temp_data("hotelrestore");
        let pia = FakePia::new(&d);
        let g = Guard::start_with(free_addr(), false);
        assert_eq!(g.status().mode, BlockMode::Off);
        g.handle("hotel start", true).unwrap();
        assert!(g.restore_pending.load(Ordering::Relaxed), "taken over before PIA's kill switch was relaxed");
        assert!(g.armed.load(Ordering::SeqCst), "block rules in place for the hotel login even with the block off");
        assert!(g.status().hotel && !g.status().restore_pending, "no 'not restored' warning during the login itself");
        // the timer ends it; PIA reports Connected before the restore ran
        let gen = g.policy.lock().unwrap().stop_hotel(Instant::now()).unwrap();
        g.apply_open();
        g.observe(Some("Connected"), Instant::now());
        assert!(g.status().blocking && firewall::open_count() == 0, "nothing opens while the kill switch is being restored");
        // the restore fails -> the guard keeps blocking whenever the VPN is down
        pia.fail_set(true);
        g.end_expired_hotel(gen);
        let st = g.status();
        assert!(st.restore_pending && st.armed && st.mode == BlockMode::Off, "{st:?}");
        g.observe(Some("Disconnected"), Instant::now());
        let st = g.status();
        assert!(st.blocking && st.reason.contains("isn't back"), "block is off, but PIA's kill switch isn't back: {st:?}");
        g.observe(Some("Connected"), Instant::now());
        assert!(!g.status().blocking, "VPN up: open");
        // restore works later -> back to off, rules gone
        pia.fail_set(false);
        g.try_restore().unwrap();
        let st = g.status();
        assert!(!st.restore_pending && !st.armed && !st.blocking, "{st:?}");
        assert_eq!(firewall::installed(), Ok(false));
        assert_eq!(pia.killswitch(), "on");
        g.shutdown();
        drop(pia);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn commands_wait_a_bounded_time_and_same_mode_is_not_reinstalled() {
        // review V3-06
        let _g = ENV_LOCK.lock().unwrap();
        let d = temp_data("busy");
        let g = Guard::start_with(free_addr(), false);
        g.handle("mode always", false).unwrap();
        let n = firewall::install_count();
        assert!(g.handle("mode always", false).unwrap().contains("already"));
        assert_eq!(firewall::install_count(), n, "the mode already in force is checked, not reinstalled");
        // a long change holds the lock -> other commands answer "busy" in bounded time
        let hold = g.op.lock().unwrap();
        let t = Instant::now();
        assert!(g.handle("mode always", false).unwrap_err().contains("busy"));
        assert!(g.handle("unlock", true).unwrap_err().contains("busy"));
        assert!(t.elapsed() < Duration::from_secs(4), "{:?}", t.elapsed());
        assert!(g.handle("status", false).is_ok(), "status never waits for the lock");
        drop(hold);
        g.handle("unlock", true).unwrap();
        g.shutdown();
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_stale_open_decision_cannot_reopen_after_a_block() {
        // review V4-02: T1 decides "open" (hotel login on); before it acts, T2
        // ends the hotel login. The allow-all must not survive.
        let _g = ENV_LOCK.lock().unwrap();
        let d = temp_data("stale");
        let g = Guard::start_with(free_addr(), false);
        g.handle("mode always", false).unwrap();
        let now = Instant::now();
        g.policy.lock().unwrap().start_hotel(now, now + Duration::from_secs(300));
        assert_eq!(firewall::open_count(), 0);
        let slot: Arc<Mutex<Option<std::thread::JoinHandle<()>>>> = Arc::new(Mutex::new(None));
        let (g2, slot2) = (g.clone(), slot.clone());
        *PAUSE.lock().unwrap() = Some(Box::new(move || {
            let t = std::thread::spawn(move || {
                g2.policy.lock().unwrap().stop_hotel(Instant::now());
                g2.apply_open();
            });
            std::thread::sleep(Duration::from_millis(300)); // T2 gets every chance to run now
            *slot2.lock().unwrap() = Some(t);
        }));
        g.apply_open(); // T1
        slot.lock().unwrap().take().unwrap().join().unwrap();
        assert_eq!(firewall::open_count(), 0, "no allow-all left over from the stale decision");
        assert!(g.status().blocking);
        g.handle("unlock", true).unwrap();
        g.shutdown();
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(unix)] // the fake piactl is a shell script
    #[test]
    fn a_due_timer_does_not_end_a_login_started_since() {
        // review V4-01, through the guard: #1 is due, #2 starts before the tick
        let _g = ENV_LOCK.lock().unwrap();
        let d = temp_data("hoteldue");
        let pia = FakePia::new(&d);
        let g = Guard::start_with(free_addr(), false);
        g.handle("mode always", false).unwrap();
        g.observe(Some("Connected"), Instant::now());
        g.handle("hotel start", true).unwrap();
        let now = Instant::now();
        g.policy.lock().unwrap().start_hotel(now, now); // #1: time is up, the tick hasn't run
        g.handle("hotel start", true).unwrap(); // #2 (finishes #1's restore first)
        pia.clear_calls();
        g.tick();
        std::thread::sleep(Duration::from_millis(300));
        let st = g.status();
        assert!(st.hotel && !st.blocking, "#2 still on: {st:?}");
        assert_eq!(pia.killswitch(), "auto");
        assert!(!pia.calls().iter().any(|c| c == "connect"), "{:?}", pia.calls());
        g.handle("hotel stop", false).unwrap();
        assert_eq!(pia.killswitch(), "on");
        g.handle("unlock", true).unwrap();
        g.shutdown();
        drop(pia);
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(unix)] // the fake piactl is a shell script
    #[test]
    fn recovery_record_survives_a_stale_settings_backup() {
        // review V4-03: guard.json is lost during a hotel login; its .bak is
        // older and says "no hotel login". The restore must still happen.
        let _g = ENV_LOCK.lock().unwrap();
        let d = temp_data("stalebak");
        let pia = FakePia::new(&d);
        let g = Guard::start_with(free_addr(), false);
        g.handle("set_users S-1-5-21-1-2-3-1001", true).unwrap(); // a settings file exists, like after an install
        g.handle("hotel start", true).unwrap();
        assert_eq!(pia.killswitch(), "auto");
        g.shutdown();
        let bak: Config = serde_json::from_str(&std::fs::read_to_string(d.join("guard.json.bak")).unwrap()).unwrap();
        assert!(!bak.hotel_active, "the backup is the pre-hotel version");
        std::fs::write(d.join("guard.json"), "{ damaged").unwrap();
        // restart: settings come from the stale .bak, the recovery record still says "on"
        let g = Guard::start_with(free_addr(), false);
        assert!(g.status().config_error.contains("last good copy"));
        // the log line comes right after the record is cleared: wait for both
        // (a slower machine once read the log in between)
        let logged = || std::fs::read_to_string(d.join("guard.log")).unwrap_or_default().contains("back to how it was");
        for _ in 0..200 {
            if pia.killswitch() == "on" && config::load_recovery() == RecoveryState::None && logged() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(pia.killswitch(), "on", "the user's kill switch came back");
        assert_eq!(config::load_recovery(), RecoveryState::None);
        assert!(logged(), "the restore was found outstanding at start");
        g.shutdown();
        drop(pia);
        let _ = std::fs::remove_dir_all(d);
    }

    #[cfg(unix)] // the fake piactl is a shell script
    #[test]
    fn restore_reports_a_firewall_sync_failure() {
        // review V4-06: PIA's kill switch is back, but the guard's rules can't
        // be brought in line (block off: they should go) - not "all done"
        let _g = ENV_LOCK.lock().unwrap();
        let d = temp_data("syncfail");
        let pia = FakePia::new(&d);
        let g = Guard::start_with(free_addr(), false);
        g.handle("hotel start", true).unwrap(); // block off + kill switch on -> recovery block in place
        assert!(g.armed.load(Ordering::SeqCst));
        firewall::fail_next_uninstall();
        let e = g.handle("hotel stop", false).unwrap_err();
        assert!(e.contains("firewall rules could not be brought in line"), "{e}");
        assert_eq!(pia.killswitch(), "on");
        assert!(!g.status().fw_error.is_empty(), "status shows the problem");
        g.sync_rules(false); // the next check tries again
        assert!(!g.armed.load(Ordering::SeqCst));
        g.shutdown();
        drop(pia);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn vpn_adapter_going_down_blocks_even_if_pia_says_connected() {
        // review V4-12, F51-07
        let _g = ENV_LOCK.lock().unwrap();
        let _quiet = NoTick::new();
        let d = temp_data("tunnel");
        let g = Guard::start_with(free_addr(), false);
        g.handle("mode always", false).unwrap();
        let up = |u: bool| crate::netif::set_test_adapters(Some(vec![crate::netif::Adapter { name: "wgpia0".into(), up: u, index: 7 }]));
        up(true);
        g.observe(Some("Connected"), Instant::now());
        let st = g.status();
        assert!(!st.blocking && st.vpn_adapter == "wgpia0 (up)" && st.tunnel_watch == "up", "checked right away: {st:?}");
        assert_eq!(st.route_via_vpn, Some(true));
        // review V60-08: the route is information only - shown, never a block by itself
        crate::netif::set_test_route(Some(3));
        g.watch_network();
        let st = g.status();
        assert!(!st.blocking && st.route_via_vpn == Some(false), "{st:?}");
        crate::netif::set_test_route(Some(7));
        up(false);
        g.watch_network();
        let st = g.status();
        assert!(st.blocking && firewall::open_count() == 0 && st.vpn_adapter.contains("DOWN") && st.tunnel_watch == "down", "{st:?}");
        g.observe(Some("Connected"), Instant::now());
        assert!(g.status().blocking, "a fresh Connected from piactl doesn't override the dead adapter");
        up(true);
        g.watch_network();
        assert!(!g.status().blocking);
        // can't look at the adapters: the last verdict stays, status says so
        crate::netif::set_test_adapters(None);
        g.watch_network();
        let st = g.status();
        assert!(!st.blocking && st.tunnel_watch == "query-failed", "{st:?}");
        // a new connection with none of PIA's adapters up: Always mode keeps blocking
        crate::netif::set_test_adapters(Some(vec![]));
        g.observe(Some("Reconnecting"), Instant::now());
        g.observe(Some("Connected"), Instant::now());
        let st = g.status();
        assert!(st.blocking && st.tunnel_watch == "checking", "{st:?}");
        std::thread::sleep(NOT_FOUND_AFTER + Duration::from_millis(100));
        g.watch_network();
        let st = g.status();
        assert!(st.blocking && st.tunnel_watch == "not-found" && st.reason.contains("can't confirm"), "{st:?}");
        crate::netif::reset_test_net();
        g.handle("unlock", true).unwrap();
        g.shutdown();
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn waits_for_a_network_before_asking_pia_to_connect() {
        let _g = ENV_LOCK.lock().unwrap();
        let _quiet = NoTick::new();
        let d = temp_data("netwait");
        crate::netif::set_test_snapshot(crate::netif::Snapshot { pia: vec![], network: None });
        let g = Guard::start_with(free_addr(), false);
        g.handle("mode startup", false).unwrap();
        g.observe(Some("Disconnected"), Instant::now());
        g.watch_network();
        let st = g.status();
        assert_eq!(st.network_ready, Some(false));
        let mut p = g.policy.lock().unwrap();
        assert!(!p.auto_connect_done() && !p.should_auto_connect(Instant::now()), "no network: not yet");
        drop(p);
        crate::netif::reset_test_net();
        g.watch_network();
        assert_eq!(g.status().network_ready, Some(true));
        // the guard's own 1-s tick may have asked already - either way, asked now
        let mut p = g.policy.lock().unwrap();
        assert!(p.auto_connect_done() || p.should_auto_connect(Instant::now()), "network up: ask now");
        drop(p);
        g.handle("unlock", true).unwrap();
        g.shutdown();
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn hotel_start_failure_rolls_back() {
        let _g = ENV_LOCK.lock().unwrap();
        let d = temp_data("hotel");
        std::env::set_var("PIALITE_PIACTL", "/nonexistent/piactl");
        let g = Guard::start_with(free_addr(), false);
        g.handle("mode always", false).unwrap();
        // PIA unreachable -> refused, nothing changed, still blocked
        assert!(g.hotel_start().unwrap_err().contains("isn't answering"));
        let st = g.status();
        assert!(!st.hotel && st.blocking, "{st:?}");
        assert!(!saved().hotel_active, "no recovery note left behind");
        g.handle("unlock", true).unwrap();
        g.shutdown();
        std::env::remove_var("PIALITE_PIACTL");
        let _ = std::fs::remove_dir_all(d);
    }
}
