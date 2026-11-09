//! When is the internet blocked? A small, deterministic state machine with no
//! Windows calls in it, so every rule is unit-tested (audit P0-03, P1-07, P1-10).
//!
//! Inputs: observations of PIA's state (each stamped with the moment it was
//! taken), sleep/wake, hotel start/stop, mode changes, the clock.
//! Output: should the temporary "allow all" be in place right now?
//!
//!   mode Off      never blocks.
//!   mode Startup  blocked after every boot / wake / service start until PIA is
//!                 seen Connected *after* that moment ("handed off"). After the
//!                 hand-off PIA's own kill switch is in charge, except: PIA's
//!                 service unreachable for 20 s, or no fresh observation for
//!                 30 s (our own monitoring broke) -> blocked again.
//!   mode Always   open only while PIA was seen Connected within the last 30 s;
//!                 any other state, or silence, blocks at once.
//!   hotel login   open until it expires, in any mode. Each login has its own
//!                 number (generation), so a late "time is up" can never end a
//!                 newer login (review V3-02), and "is it due?" and "end it" are
//!                 one step under one lock (expire_hotel_if_due, V4-01). Ending it (by hand or timer)
//!                 counts as a fresh start: blocked again until PIA is seen
//!                 Connected afterwards, in Startup mode too (review N-02).
//!   restoring     from the end of a hotel login until the guard has tried to
//!                 put PIA's kill switch back: nothing opens, not even for a
//!                 Connected report (review V3-03).
//!   strict        from BEFORE a hotel login changes PIA's kill switch until it
//!                 is verified back: Off and Startup behave like Always - the
//!                 guard enforces what PIA's kill switch no longer does
//!                 (review N-06, V3-03, V3-10).
//!   tunnel        the guard's own look at PIA's network adapter (V4-12,
//!                 F51-07). Always mode opens only when PIA says Connected AND
//!                 the adapter is observed up (what Windows reports - not a
//!                 test of the encrypted tunnel itself); unchecked, down or not
//!                 found = blocked. Startup mode keeps its meaning - PIA takes
//!                 over once it connects - so only a tunnel already known to be
//!                 down or missing stops the hand-off.
//!   network       PIA is asked to connect once a network is up (or after 30 s
//!                 without one), and if the network comes up while PIA was
//!                 already retrying, its attempt is restarted: PIA retries only
//!                 every 10 s after its first two tries (its source:
//!                 vpnstate.h), so a network that appears mid-wait otherwise
//!                 costs up to 10 s.
//!
//! Nothing is assumed from OS uptime or from old observations.

use pialite_common::status::BlockMode;
use std::time::{Duration, Instant};

/// An observation older than this is not trusted.
pub const STALE: Duration = Duration::from_secs(30);
/// Startup mode: PIA's service unreachable this long -> block again.
pub const UNREACHABLE_REARM: Duration = Duration::from_secs(20);
/// After boot/wake, asking PIA to connect is only done within this window.
pub const AUTO_CONNECT_WINDOW: Duration = Duration::from_secs(300);
/// How often PIA's state is actively checked (on top of its change events).
pub const PROBE_EVERY: Duration = Duration::from_secs(10);
/// PIA "connecting" this long while blocked -> ask it to reconnect.
pub const KICK_AFTER: Duration = Duration::from_secs(90);
pub const KICKS_MAX: u8 = 2;
/// No usable network seen: ask PIA to connect anyway after this long.
pub const NET_WAIT_MAX: Duration = Duration::from_secs(30);
/// PIA must have been retrying this long before the network came up for a
/// restart to help (a newer attempt already has the network).
pub const NET_KICK_LEAD: Duration = Duration::from_secs(2);
/// Network up this long and PIA still not connected -> restart its attempt.
pub const NET_KICK_AFTER: Duration = Duration::from_secs(1);
/// Never two restarts closer together than this.
pub const KICK_GAP: Duration = Duration::from_secs(15);

/// The guard's own look at PIA's network adapter (review V4-12, F51-07).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tunnel {
    /// Not checked for this connection yet (or the VPN is not connected).
    #[default]
    Unchecked,
    /// The adapter carrying this connection is up.
    Up,
    /// It was up and went down or disappeared.
    Down,
    /// PIA says Connected, but none of PIA's adapters is up.
    NotFound,
}

/// PIA is trying to connect (any connecting-ish state).
pub fn trying(state: Option<&str>) -> bool {
    matches!(
        state,
        Some("Connecting" | "StillConnecting" | "Reconnecting" | "StillReconnecting" | "Interrupted" | "DisconnectingToReconnect")
    )
}

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    HandedOff,
    Rearmed(&'static str),
    /// The hotel login with this number ran out of time (and was ended).
    HotelExpired(u64),
}

#[derive(Debug, Clone)]
struct Obs {
    state: Option<String>,
    at: Instant,
}

#[derive(Debug)]
pub struct Policy {
    mode: BlockMode,
    connect_at_boot: bool,
    handed_off: bool,
    rearmed_at: Instant,
    last: Option<Obs>,
    unreachable_since: Option<Instant>,
    hotel_until: Option<Instant>,
    hotel_gen: u64,
    restoring: bool,
    strict: bool,
    tunnel: Tunnel,
    auto_connect_done: bool,
    state_since: Option<Instant>,
    /// Since when PIA has been trying to connect (any connecting-ish state).
    trying_since: Option<Instant>,
    /// Number of the current connection attempt series (+1 each time PIA
    /// starts trying again): a restart is only ever done for the attempt it
    /// was decided for (review V60-01).
    attempt_gen: u64,
    kicks: u8,
    last_kick: Option<Instant>,
    /// Is there a usable network? None = not known (counts as yes).
    network: Option<bool>,
    /// When the network last came up.
    network_since: Option<Instant>,
    /// When it was last seen gone (the 30 s fallback counts from here or from
    /// boot/wake, whichever is later - review V60-05).
    network_lost_at: Option<Instant>,
    /// The restart for the current network-up has been done.
    net_kicked: bool,
    /// The user disconnected PIA from the tray (told by the tray, review
    /// FINAL-02): no automatic connect or restart until they connect again
    /// or the next boot/wake. The block itself is unchanged.
    user_off: bool,
    /// Since that Disconnect, PIA was seen DISCONNECTED: only a Connected
    /// after that is a new connection (review V63-02). "Service not
    /// reachable" (None) proves nothing and doesn't count (V64-01).
    user_off_seen_down: bool,
}

impl Policy {
    /// Service start counts as a fresh boot: blocked until PIA is seen connected.
    pub fn new(mode: BlockMode, connect_at_boot: bool, now: Instant) -> Policy {
        Policy {
            mode,
            connect_at_boot,
            handed_off: false,
            rearmed_at: now,
            last: None,
            unreachable_since: None,
            hotel_until: None,
            hotel_gen: 0,
            restoring: false,
            strict: false,
            tunnel: Tunnel::Unchecked,
            auto_connect_done: false,
            state_since: None,
            trying_since: None,
            attempt_gen: 0,
            kicks: 0,
            last_kick: None,
            network: None,
            network_since: None,
            network_lost_at: None,
            net_kicked: false,
            user_off: false,
            user_off_seen_down: false,
        }
    }

    pub fn set_mode(&mut self, mode: BlockMode) {
        self.mode = mode;
    }

    /// The user pressed Disconnect (true) or Connect (false) in the tray.
    /// Either way a restart already decided is for an attempt that is no
    /// longer the current one (review V63-02).
    pub fn note_user(&mut self, disconnect: bool) {
        self.user_off = disconnect;
        // only a "Disconnected" reported AFTER the press counts - a cached one
        // may be stale while the tray already saw PIA connected (review V65-03)
        self.user_off_seen_down = false;
        self.attempt_gen += 1;
    }

    #[cfg(test)]
    pub fn auto_connect_done(&self) -> bool {
        self.auto_connect_done
    }

    pub fn user_off(&self) -> bool {
        self.user_off
    }

    pub fn set_connect_at_boot(&mut self, on: bool) {
        self.connect_at_boot = on;
    }

    /// PIA's own kill switch isn't how the user had it (changed for a hotel
    /// login, not verified back yet): Off and Startup block like Always.
    pub fn set_strict(&mut self, on: bool) {
        self.strict = on;
    }

    /// The mode that decides blocking right now.
    pub fn effective(&self) -> BlockMode {
        if self.strict {
            BlockMode::Always
        } else {
            self.mode
        }
    }

    /// A report of PIA's state taken at `at` (None = service unreachable).
    pub fn observe(&mut self, state: Option<&str>, at: Instant) -> Vec<Event> {
        // ignore anything older than what we already have
        if self.last.as_ref().is_some_and(|l| l.at > at) {
            return vec![];
        }
        match state {
            Some(_) => self.unreachable_since = None,
            None => {
                self.unreachable_since.get_or_insert(at);
            }
        }
        let prev = self.last.as_ref().and_then(|o| o.state.clone());
        if self.last.as_ref().map(|o| o.state.as_deref()) != Some(state) {
            self.state_since = Some(at);
            if state != Some("Connected") {
                // a new connection gets its adapter checked afresh
                self.tunnel = Tunnel::Unchecked;
            }
        }
        if !trying(state) {
            self.trying_since = None;
        } else if !trying(prev.as_deref()) || self.trying_since.is_none() {
            self.trying_since = Some(at);
            self.attempt_gen += 1;
        }
        self.last = Some(Obs { state: state.map(str::to_string), at });
        // the user's "off" ends with a NEW connection (by whoever) - not with
        // more "Connected" reports from before the disconnect took (V63-02)
        if self.user_off {
            if state == Some("Disconnected") {
                self.user_off_seen_down = true;
            } else if state == Some("Connected") && self.user_off_seen_down && prev.as_deref() != Some("Connected") {
                self.user_off = false;
            }
        }
        let mut ev = vec![];
        // during a restore nothing is handed off - PIA's kill switch may not be back yet
        let tunnel_bad = matches!(self.tunnel, Tunnel::Down | Tunnel::NotFound);
        if state == Some("Connected") && at >= self.rearmed_at && !self.handed_off && !self.restoring && !tunnel_bad {
            self.handed_off = true;
            ev.push(Event::HandedOff);
        }
        ev
    }

    /// Sleep, hibernate (incl. Fast Startup "shutdown"), wake.
    pub fn rearm(&mut self, now: Instant, why: &'static str) -> Vec<Event> {
        let was = self.handed_off;
        self.handed_off = false;
        self.rearmed_at = now;
        self.auto_connect_done = false;
        self.user_off = false;
        self.kicks = 0;
        self.last_kick = None;
        if was {
            vec![Event::Rearmed(why)]
        } else {
            vec![]
        }
    }

    fn fresh(&self, now: Instant) -> Option<&Obs> {
        self.last.as_ref().filter(|o| o.at >= self.rearmed_at && now.saturating_duration_since(o.at) <= STALE)
    }

    /// PIA says Connected (freshly) - nothing about the adapter.
    fn pia_connected(&self, now: Instant) -> bool {
        self.fresh(now).is_some_and(|o| o.state.as_deref() == Some("Connected"))
    }

    /// PIA says Connected AND its adapter is seen up (what Always mode needs).
    pub fn connected_fresh(&self, now: Instant) -> bool {
        self.tunnel == Tunnel::Up && self.pia_connected(now)
    }

    /// What the guard saw of PIA's adapter for the current connection.
    pub fn set_tunnel(&mut self, t: Tunnel) {
        self.tunnel = t;
    }

    pub fn tunnel(&self) -> Tunnel {
        self.tunnel
    }

    /// When PIA's current state began.
    pub fn state_since(&self) -> Option<Instant> {
        self.state_since
    }

    /// Is a network up? None = couldn't tell (keeps the last answer).
    pub fn set_network(&mut self, ready: Option<bool>, now: Instant) {
        let Some(ready) = ready else { return };
        if ready && self.network != Some(true) {
            self.network_since = Some(now);
            self.net_kicked = false;
        }
        if !ready {
            self.network_since = None;
            if self.network != Some(false) {
                self.network_lost_at = Some(now);
            }
        }
        self.network = Some(ready);
    }

    pub fn network(&self) -> Option<bool> {
        self.network
    }

    /// Housekeeping, call about once a second.
    pub fn tick(&mut self, now: Instant) -> Vec<Event> {
        let mut ev = vec![];
        if self.handed_off {
            if self.unreachable_since.is_some_and(|t| now.saturating_duration_since(t) > UNREACHABLE_REARM) {
                ev.extend(self.rearm(now, "PIA's service is not responding"));
            } else if self.last.as_ref().is_none_or(|o| now.saturating_duration_since(o.at) > STALE) {
                ev.extend(self.rearm(now, "lost track of PIA's state"));
            }
        }
        ev
    }

    /// If the running hotel login's time is up, end it - checked and done in
    /// one step, so a login started a moment ago can't be ended by mistake
    /// (review V4-01). Returns its number.
    pub fn expire_hotel_if_due(&mut self, now: Instant) -> Option<u64> {
        if self.hotel_until.is_some_and(|t| now >= t) {
            self.stop_hotel(now)
        } else {
            None
        }
    }

    /// Should the temporary allow-all be in place?
    pub fn want_open(&self, now: Instant) -> bool {
        if self.hotel_active(now) {
            return true;
        }
        if self.restoring {
            return false;
        }
        match self.effective() {
            BlockMode::Off => false,
            BlockMode::Startup => self.handed_off,
            BlockMode::Always => self.connected_fresh(now),
        }
    }

    pub fn blocking(&self, now: Instant) -> bool {
        self.effective() != BlockMode::Off && !self.want_open(now)
    }

    pub fn reason(&self, now: Instant) -> String {
        if self.hotel_active(now) {
            return "hotel login: VPN off, traffic allowed outside the VPN until it ends".into();
        }
        if self.restoring && self.effective() != BlockMode::Off {
            return "blocked: hotel login just ended - putting PIA's kill switch back first".into();
        }
        if self.blocking(now) && self.pia_connected(now) {
            match self.tunnel {
                Tunnel::Down => return "blocked: PIA says Connected, but its network adapter is down".into(),
                Tunnel::NotFound => {
                    return "blocked: PIA says Connected, but none of its network adapters is up - PIA Lite can't confirm the tunnel".into()
                }
                Tunnel::Unchecked if self.effective() == BlockMode::Always => {
                    return "blocked: PIA says Connected - checking its network adapter".into()
                }
                _ => {}
            }
        }
        if self.strict && self.mode != BlockMode::Always {
            return if self.blocking(now) {
                "blocked: VPN not connected and PIA's kill switch isn't back after the hotel login - the guard blocks until it is".into()
            } else {
                "VPN connected (the guard blocks whenever it isn't, until PIA's kill switch is back)".into()
            };
        }
        match (self.mode, self.blocking(now)) {
            (BlockMode::Off, _) => "block is off".into(),
            (BlockMode::Startup, true) => "blocked until the VPN connects (startup/wake)".into(),
            (BlockMode::Startup, false) => "VPN connected since startup - PIA's own kill switch is in charge".into(),
            (BlockMode::Always, true) => "blocked: VPN not connected".into(),
            (BlockMode::Always, false) => "VPN connected".into(),
        }
    }

    /// Ask PIA to connect? At most once per boot/wake, only BEFORE the first
    /// connection since then (a later Disconnect is the user's choice), only
    /// when PIA is freshly seen Disconnected, and once a network is up (asked
    /// too early, PIA falls into its 10-second retry rhythm) - or after
    /// NET_WAIT_MAX without one, in case the network check is wrong.
    pub fn should_auto_connect(&mut self, now: Instant) -> bool {
        let disconnected = self.fresh(now).is_some_and(|o| o.state.as_deref() == Some("Disconnected"));
        // waited for a network since boot/wake (or since it went away) - not
        // since PIA's state last changed, which can be long before a wake (V60-05)
        let wait_from = self.network_lost_at.map_or(self.rearmed_at, |t| t.max(self.rearmed_at));
        let waited = now.saturating_duration_since(wait_from) >= NET_WAIT_MAX;
        let network_ok = self.network != Some(false) || waited;
        // the window counts from boot/wake, or from when the network came up
        let from = self.network_since.map_or(self.rearmed_at, |t| t.max(self.rearmed_at));
        if self.effective() != BlockMode::Off
            && self.connect_at_boot
            && !self.auto_connect_done
            && !self.user_off
            && !self.handed_off
            && disconnected
            && network_ok
            && !self.hotel_active(now)
            && now.saturating_duration_since(from) < AUTO_CONNECT_WINDOW
        {
            self.auto_connect_done = true;
            return true;
        }
        false
    }

    /// PIA stuck "connecting" for a long time while we block: ask it to
    /// reconnect (what opening PIA's window seems to do). At most KICKS_MAX
    /// times per boot/wake; never lifts the block.
    pub fn should_kick(&mut self, now: Instant) -> bool {
        let stuck = self.fresh(now).is_some_and(|o| {
            matches!(o.state.as_deref(), Some("Connecting" | "StillConnecting" | "Reconnecting" | "StillReconnecting" | "Interrupted"))
        });
        let long = |t: Option<Instant>| t.is_none_or(|t| now.saturating_duration_since(t) >= KICK_AFTER);
        let gap = self.last_kick.is_none_or(|t| now.saturating_duration_since(t) >= KICK_GAP);
        if self.effective() != BlockMode::Off
            && gap
            && !self.user_off
            && !self.restoring
            && !self.handed_off
            && !self.hotel_active(now)
            && self.kicks < KICKS_MAX
            && stuck
            && self.state_since.is_some()
            && long(self.state_since)
            && long(self.last_kick)
        {
            self.kicks += 1;
            self.last_kick = Some(now);
            return true;
        }
        false
    }

    pub fn kicks(&self) -> u8 {
        self.kicks
    }

    /// The current connection attempt's number (see attempt_gen).
    pub fn attempt_gen(&self) -> u64 {
        self.attempt_gen
    }

    /// Is the guard waiting for the VPN (blocking until PIA connects)?
    fn guard_waits(&self) -> bool {
        self.effective() == BlockMode::Always || !self.handed_off
    }

    /// Right before a restart disconnects PIA: is it STILL the same, stuck
    /// attempt, and still the guard's business? (review V60-01) Anything
    /// else cancels it: PIA connected meanwhile, the user disconnected, a
    /// newer attempt, block off, a hotel login, a kill switch restore.
    pub fn kick_still_valid(&self, gen: u64, now: Instant) -> bool {
        let still_trying = self.fresh(now).is_some_and(|o| trying(o.state.as_deref()));
        still_trying
            && !self.user_off
            && self.attempt_gen == gen
            && self.effective() != BlockMode::Off
            && !self.restoring
            && !self.hotel_active(now)
            && self.guard_waits()
    }

    /// After the restart's disconnect: may it connect again? Only when PIA
    /// reported Disconnected after the disconnect was sent (`since`) - never
    /// blindly - and the guard still waits for the VPN.
    pub fn may_reconnect(&self, since: Instant, now: Instant) -> bool {
        let disconnected = self.fresh(now).is_some_and(|o| o.at >= since && o.state.as_deref() == Some("Disconnected"));
        disconnected
            && !self.user_off
            && self.effective() != BlockMode::Off
            && !self.restoring
            && !self.hotel_active(now)
            && self.guard_waits()
    }

    /// PIA's state if it was reported since the last boot/wake/hotel end and
    /// isn't stale; None = no such report (review V64-02: a decision must not
    /// rest on a report from before the situation it is about).
    pub fn fresh_state(&self, now: Instant) -> Option<Option<String>> {
        self.fresh(now).map(|o| o.state.clone())
    }

    /// PIA's last reported state and when it was observed.
    pub fn last_observed(&self) -> Option<(Option<String>, Instant)> {
        self.last.as_ref().map(|o| (o.state.clone(), o.at))
    }

    /// The network just came up while PIA was already retrying (it started
    /// before the network was there): restart PIA's attempt now instead of
    /// waiting for its next 10-second retry. Once per network-up, while the
    /// guard is blocking for want of the VPN; never lifts the block.
    pub fn should_net_kick(&mut self, now: Instant) -> bool {
        let (Some(tried), Some(net)) = (self.trying_since, self.network_since) else { return false };
        let still_trying = self.fresh(now).is_some_and(|o| trying(o.state.as_deref()));
        if self.effective() != BlockMode::Off
            && self.guard_waits()
            && !self.restoring
            && !self.hotel_active(now)
            && !self.user_off
            && !self.net_kicked
            && still_trying
            && tried + NET_KICK_LEAD <= net
            && now.saturating_duration_since(net) >= NET_KICK_AFTER
            && self.last_kick.is_none_or(|t| now.saturating_duration_since(t) >= KICK_GAP)
        {
            self.net_kicked = true;
            self.last_kick = Some(now);
            return true;
        }
        false
    }

    /// Time to check PIA's state actively?
    pub fn needs_probe(&self, now: Instant, last_probe: Option<Instant>) -> bool {
        match last_probe {
            None => true,
            Some(p) if p < self.rearmed_at => true, // nothing checked since boot/wake
            Some(p) => now.saturating_duration_since(p) >= PROBE_EVERY,
        }
    }

    /// Start a hotel login, or extend the running one. Returns its number.
    pub fn start_hotel(&mut self, now: Instant, until: Instant) -> u64 {
        if !self.hotel_active(now) {
            self.hotel_gen += 1;
        }
        self.hotel_until = Some(until);
        self.restoring = false; // an earlier login's restore was finished before this one started
                                // a hotel login is the user's own choice and ends with a reconnect
        self.user_off = false;
        self.hotel_gen
    }

    /// End hotel login (by hand or because time is up). Returns its number if
    /// one was on. Re-arms: the old hand-off is void, the block is back until
    /// PIA is seen Connected after `now` (review N-02), and nothing opens until
    /// the guard has tried to restore PIA's kill switch (V3-03). No automatic
    /// connect - the guard reconnects after the restore (N-06).
    pub fn stop_hotel(&mut self, now: Instant) -> Option<u64> {
        self.hotel_until.take()?;
        self.handed_off = false;
        self.rearmed_at = now;
        self.auto_connect_done = true;
        self.kicks = 0;
        self.last_kick = None;
        self.restoring = true;
        Some(self.hotel_gen)
    }

    /// The number of the latest hotel login.
    pub fn hotel_gen(&self) -> u64 {
        self.hotel_gen
    }

    /// The guard finished its restore attempt after a hotel login.
    pub fn restore_done(&mut self) {
        self.restoring = false;
    }

    pub fn restoring(&self) -> bool {
        self.restoring
    }

    pub fn hotel_active(&self, now: Instant) -> bool {
        self.hotel_until.is_some_and(|t| now < t)
    }

    pub fn hotel_left(&self, now: Instant) -> Duration {
        self.hotel_until.map(|t| t.saturating_duration_since(now)).unwrap_or_default()
    }

    pub fn pia_state(&self) -> Option<String> {
        self.last.as_ref().and_then(|o| o.state.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PIA says Connected and the guard saw its adapter up (what Always needs).
    fn connect(p: &mut Policy, at: Instant) {
        p.observe(Some("Connected"), at);
        p.set_tunnel(Tunnel::Up);
    }

    fn s(secs: u64, t0: Instant) -> Instant {
        t0 + Duration::from_secs(secs)
    }

    #[test]
    fn startup_blocks_until_connected_then_hands_off() {
        let t0 = Instant::now();
        let mut p = Policy::new(BlockMode::Startup, false, t0);
        assert!(p.blocking(t0));
        p.observe(Some("Connecting"), s(2, t0));
        assert!(p.blocking(s(2, t0)));
        assert_eq!(p.observe(Some("Connected"), s(5, t0)), vec![Event::HandedOff]);
        assert!(!p.blocking(s(5, t0)));
        // startup mode: a later disconnect is PIA's kill switch's job
        p.observe(Some("Disconnected"), s(8, t0));
        assert!(!p.blocking(s(8, t0)));
    }

    #[test]
    fn always_mode_reblocks_on_any_non_connected_state() {
        let t0 = Instant::now();
        let mut p = Policy::new(BlockMode::Always, false, t0);
        connect(&mut p, s(1, t0));
        assert!(!p.blocking(s(1, t0)));
        let mut t = 1;
        for st in ["Disconnected", "Interrupted", "Reconnecting", "Disconnecting"] {
            t += 1;
            p.observe(Some(st), s(t, t0));
            assert!(p.blocking(s(t, t0)), "{st} must block");
            t += 1;
            connect(&mut p, s(t, t0));
            assert!(!p.blocking(s(t, t0)));
        }
        p.observe(None, s(t + 1, t0));
        assert!(p.blocking(s(t + 1, t0)), "PIA unreachable must block");
        // an older report arriving late is ignored
        p.observe(Some("Connected"), s(1, t0));
        assert!(p.blocking(s(t + 1, t0)));
    }

    #[test]
    fn stale_or_hung_monitoring_fails_safe() {
        let t0 = Instant::now();
        // always: Connected seen once, then silence
        let mut p = Policy::new(BlockMode::Always, false, t0);
        connect(&mut p, s(1, t0));
        assert!(!p.blocking(s(30, t0)));
        assert!(p.blocking(s(32, t0)), "older than 30 s is not trusted");
        // startup: handed off, then silence
        let mut p = Policy::new(BlockMode::Startup, false, t0);
        p.observe(Some("Connected"), s(1, t0));
        assert!(p.tick(s(20, t0)).is_empty());
        assert_eq!(p.tick(s(40, t0)), vec![Event::Rearmed("lost track of PIA's state")]);
        assert!(p.blocking(s(40, t0)));
    }

    #[test]
    fn pia_service_gone_reblocks_startup_mode() {
        let t0 = Instant::now();
        let mut p = Policy::new(BlockMode::Startup, false, t0);
        p.observe(Some("Connected"), s(1, t0));
        p.observe(None, s(5, t0));
        p.observe(None, s(15, t0));
        assert!(!p.blocking(s(15, t0)), "short blips are tolerated");
        p.observe(None, s(26, t0));
        assert_eq!(p.tick(s(26, t0)), vec![Event::Rearmed("PIA's service is not responding")]);
        assert!(p.blocking(s(26, t0)));
    }

    #[test]
    fn restart_does_not_assume_connected() {
        // a service restart is a new Policy: no uptime heuristics, blocked until seen
        let t0 = Instant::now();
        let p = Policy::new(BlockMode::Startup, false, t0);
        assert!(p.blocking(s(3600, t0)));
    }

    #[test]
    fn wake_needs_a_fresh_connected() {
        let t0 = Instant::now();
        let mut p = Policy::new(BlockMode::Startup, false, t0);
        p.observe(Some("Connected"), s(1, t0));
        assert_eq!(p.rearm(s(100, t0), "woke up"), vec![Event::Rearmed("woke up")]);
        assert!(p.blocking(s(100, t0)));
        // a check that started before the wake-up doesn't count
        assert!(p.observe(Some("Connected"), s(99, t0)).is_empty());
        assert!(p.blocking(s(101, t0)));
        assert!(p.needs_probe(s(101, t0), Some(s(99, t0))), "probe again right after wake");
        assert_eq!(p.observe(Some("Connected"), s(102, t0)), vec![Event::HandedOff]);
        assert!(!p.blocking(s(102, t0)));
    }

    #[test]
    fn hotel_overrides_and_expires() {
        let t0 = Instant::now();
        let mut p = Policy::new(BlockMode::Always, false, t0);
        p.observe(Some("Disconnected"), s(1, t0));
        assert!(p.blocking(s(1, t0)));
        let g1 = p.start_hotel(s(1, t0), s(181, t0));
        assert!(!p.blocking(s(2, t0)));
        assert_eq!(p.hotel_left(s(61, t0)), Duration::from_secs(120));
        assert_eq!(p.start_hotel(s(61, t0), s(181, t0)), g1, "extending keeps the number");
        assert_eq!(p.expire_hotel_if_due(s(180, t0)), None, "not yet");
        assert!(p.blocking(s(181, t0)), "expired hotel login no longer opens");
        assert_eq!(p.expire_hotel_if_due(s(181, t0)), Some(g1));
        assert_eq!(p.stop_hotel(s(182, t0)), None, "idempotent");
        // a new login gets a new number (review V3-02)
        let g2 = p.start_hotel(s(190, t0), s(370, t0));
        assert!(g2 > g1);
        assert!(!p.restoring(), "a new login starts after the old one's restore");
    }

    #[test]
    fn hotel_exit_rearms_startup_mode() {
        // review N-02: Startup -> Connected -> hotel -> Disconnected -> hotel ends
        for expire in [false, true] {
            let t0 = Instant::now();
            let mut p = Policy::new(BlockMode::Startup, true, t0);
            p.observe(Some("Connected"), s(1, t0));
            assert!(!p.blocking(s(1, t0)), "handed off");
            p.start_hotel(s(2, t0), s(301, t0));
            p.observe(Some("Disconnected"), s(3, t0));
            assert!(!p.blocking(s(100, t0)), "hotel login open");
            let (end, ended) = if expire {
                p.observe(Some("Disconnected"), s(299, t0)); // the guard probes every 10 s
                assert!(p.tick(s(301, t0)).is_empty());
                (s(301, t0), p.expire_hotel_if_due(s(301, t0)))
            } else {
                (s(200, t0), p.stop_hotel(s(200, t0)))
            };
            assert!(ended.is_some());
            assert!(p.blocking(end), "blocked again the moment hotel login ends (expire={expire})");
            // review V3-03: a Connected report during the restore doesn't open
            p.observe(Some("Connected"), end);
            assert!(p.blocking(end), "nothing opens while the kill switch is being restored");
            assert!(p.reason(end).contains("putting PIA's kill switch back"));
            assert!(!p.observe(Some("Connected"), end).contains(&Event::HandedOff), "no hand-off during the restore");
            p.restore_done();
            p.observe(Some("Disconnected"), end + Duration::from_secs(1));
            assert!(p.blocking(end + Duration::from_secs(1)));
            assert!(!p.should_auto_connect(end + Duration::from_secs(1)), "reconnect is the guard's call after restore");
            // an observation from before the end doesn't count
            assert!(p.observe(Some("Connected"), end - Duration::from_secs(1)).is_empty());
            assert!(p.blocking(end + Duration::from_secs(2)));
            assert_eq!(p.observe(Some("Connected"), end + Duration::from_secs(5)), vec![Event::HandedOff]);
            assert!(!p.blocking(end + Duration::from_secs(5)));
        }
    }

    #[test]
    fn a_due_timer_never_ends_a_login_started_since() {
        // review V4-01: #1 is due, but #2 was started before the timer acted
        let t0 = Instant::now();
        let mut p = Policy::new(BlockMode::Always, false, t0);
        let g1 = p.start_hotel(t0, s(10, t0));
        let g2 = p.start_hotel(s(10, t0), s(190, t0)); // #1 already over at 10 s: a new login
        assert!(g2 > g1);
        assert_eq!(p.expire_hotel_if_due(s(10, t0)), None, "the newer login is not ended");
        assert!(p.hotel_active(s(11, t0)) && !p.restoring());
        // extending right at the deadline keeps the same login going
        assert_eq!(p.start_hotel(s(189, t0), s(369, t0)), g2);
        assert_eq!(p.expire_hotel_if_due(s(190, t0)), None);
        assert_eq!(p.expire_hotel_if_due(s(369, t0)), Some(g2));
    }

    #[test]
    fn always_mode_needs_the_tunnel_seen_up() {
        // review V4-12, F51-07: PIA's word alone isn't enough in Always mode
        let t0 = Instant::now();
        let mut p = Policy::new(BlockMode::Always, false, t0);
        p.observe(Some("Connected"), s(1, t0));
        assert!(p.blocking(s(1, t0)) && p.reason(s(1, t0)).contains("checking"), "{}", p.reason(s(1, t0)));
        p.set_tunnel(Tunnel::Up);
        assert!(!p.blocking(s(1, t0)));
        p.set_tunnel(Tunnel::Down);
        assert!(p.blocking(s(2, t0)) && p.reason(s(2, t0)).contains("adapter is down"));
        p.observe(Some("Connected"), s(3, t0));
        assert!(p.blocking(s(3, t0)), "a fresh Connected doesn't override a dead adapter");
        p.set_tunnel(Tunnel::Up);
        assert!(!p.blocking(s(4, t0)));
        p.set_tunnel(Tunnel::NotFound);
        assert!(p.blocking(s(4, t0)) && p.reason(s(4, t0)).contains("can't confirm"));
        // a new connection is checked afresh
        p.observe(Some("Reconnecting"), s(5, t0));
        assert_eq!(p.tunnel(), Tunnel::Unchecked);
        p.observe(Some("Connected"), s(6, t0));
        assert!(p.blocking(s(6, t0)));
        // Startup mode keeps its meaning: PIA takes over once connected...
        let mut q = Policy::new(BlockMode::Startup, false, t0);
        assert_eq!(q.observe(Some("Connected"), s(1, t0)), vec![Event::HandedOff]);
        // ...unless the tunnel is already known to be down or missing
        let mut q = Policy::new(BlockMode::Startup, false, t0);
        q.set_tunnel(Tunnel::Down);
        assert!(q.observe(Some("Connected"), s(1, t0)).is_empty());
        q.set_tunnel(Tunnel::Up);
        assert_eq!(q.observe(Some("Connected"), s(2, t0)), vec![Event::HandedOff]);
    }

    #[test]
    fn asks_pia_to_connect_once_a_network_is_up() {
        let t0 = Instant::now();
        let mut p = Policy::new(BlockMode::Startup, true, t0);
        p.set_network(Some(false), t0);
        p.observe(Some("Disconnected"), s(1, t0));
        assert!(!p.should_auto_connect(s(2, t0)), "no network yet: PIA would only fall into its 10 s retries");
        p.set_network(Some(true), s(5, t0));
        assert!(p.should_auto_connect(s(5, t0)));
        assert!(!p.should_auto_connect(s(6, t0)), "once");
        // a network check that never says yes: asked anyway after NET_WAIT_MAX
        // (counted from boot/wake or from when the network went away)
        let mut q = Policy::new(BlockMode::Startup, true, t0);
        q.set_network(Some(false), t0);
        q.observe(Some("Disconnected"), s(1, t0));
        assert!(!q.should_auto_connect(s(29, t0)));
        assert!(q.should_auto_connect(s(30, t0)));
        // review V60-05: after a wake, PIA's "Disconnected" from long before
        // the sleep doesn't count as having waited
        let mut w = Policy::new(BlockMode::Startup, true, t0);
        w.set_network(Some(true), t0);
        w.observe(Some("Disconnected"), s(1, t0));
        assert!(w.should_auto_connect(s(1, t0)));
        w.observe(Some("Connected"), s(2, t0));
        w.observe(Some("Disconnected"), s(3, t0)); // state since 3 s
        w.rearm(s(500, t0), "woke up");
        w.set_network(Some(false), s(500, t0));
        w.observe(Some("Disconnected"), s(501, t0)); // same state, still "since 3 s"
        assert!(!w.should_auto_connect(s(501, t0)), "no network yet after the wake");
        assert!(!w.should_auto_connect(s(529, t0)));
        assert!(w.should_auto_connect(s(530, t0)), "30 s after the wake");
        // can't tell (the look failed): don't wait, as before
        let mut r = Policy::new(BlockMode::Startup, true, t0);
        r.set_network(None, t0);
        r.observe(Some("Disconnected"), s(1, t0));
        assert!(r.should_auto_connect(s(1, t0)));
        // the 5-minute window counts from when the network came up
        let mut w = Policy::new(BlockMode::Startup, true, t0);
        w.set_network(Some(false), t0);
        w.observe(Some("Disconnected"), s(1, t0));
        w.set_network(Some(true), s(400, t0));
        w.observe(Some("Disconnected"), s(400, t0));
        assert!(w.should_auto_connect(s(400, t0)), "signed in late: still asked");
    }

    #[test]
    fn restarts_pia_when_the_network_comes_up_mid_retry() {
        let t0 = Instant::now();
        let mut p = Policy::new(BlockMode::Startup, true, t0);
        p.set_network(Some(false), t0);
        p.observe(Some("Connecting"), s(1, t0)); // asked with no network: PIA retries every 10 s
        p.observe(Some("StillConnecting"), s(20, t0));
        p.set_network(Some(true), s(40, t0));
        assert!(!p.should_net_kick(s(40, t0)), "a moment first, PIA may be mid-try");
        assert!(p.should_net_kick(s(41, t0)));
        assert!(!p.should_net_kick(s(42, t0)), "once per network-up");
        // the restart itself: a new attempt, with the network there - left alone
        p.observe(Some("Disconnected"), s(42, t0));
        p.observe(Some("Connecting"), s(42, t0));
        assert!(!p.should_net_kick(s(50, t0)));
        // the network drops and comes back while PIA still tries: again (after KICK_GAP)
        p.set_network(Some(false), s(51, t0));
        p.set_network(Some(true), s(52, t0));
        assert!(p.should_net_kick(s(57, t0)));
        // an attempt that began after the network was up is left alone
        let mut q = Policy::new(BlockMode::Startup, true, t0);
        q.set_network(Some(true), t0);
        q.observe(Some("Connecting"), s(1, t0));
        assert!(!q.should_net_kick(s(9, t0)));
        // after the hand-off, Startup mode leaves reconnects to PIA; Always keeps them fast
        for (mode, want) in [(BlockMode::Startup, false), (BlockMode::Always, true), (BlockMode::Off, false)] {
            let mut r = Policy::new(mode, true, t0);
            r.set_network(Some(false), t0);
            r.observe(Some("Connected"), s(1, t0));
            r.observe(Some("Reconnecting"), s(2, t0));
            r.set_network(Some(true), s(10, t0));
            assert_eq!(r.should_net_kick(s(11, t0)), want, "{mode:?}");
        }
        // never during a hotel login
        let mut h = Policy::new(BlockMode::Always, true, t0);
        h.set_network(Some(false), t0);
        h.observe(Some("Connecting"), s(1, t0));
        h.start_hotel(s(2, t0), s(200, t0));
        h.set_network(Some(true), s(10, t0));
        assert!(!h.should_net_kick(s(11, t0)));
    }

    #[test]
    fn strict_off_mode_blocks_like_always() {
        // review V3-10: block "off", but PIA's kill switch isn't back -> the guard blocks
        let t0 = Instant::now();
        let mut p = Policy::new(BlockMode::Off, false, t0);
        assert!(!p.blocking(t0));
        p.set_strict(true);
        assert_eq!(p.effective(), BlockMode::Always);
        assert!(p.blocking(s(1, t0)));
        connect(&mut p, s(2, t0));
        assert!(!p.blocking(s(2, t0)));
        p.observe(Some("Disconnected"), s(3, t0));
        assert!(p.blocking(s(3, t0)) && p.reason(s(3, t0)).contains("isn't back"));
        p.set_strict(false);
        assert!(!p.blocking(s(4, t0)), "back to off once restored");
    }

    #[test]
    fn strict_startup_blocks_like_always() {
        let t0 = Instant::now();
        let mut p = Policy::new(BlockMode::Startup, false, t0);
        p.set_strict(true);
        connect(&mut p, s(1, t0));
        assert!(!p.blocking(s(1, t0)));
        p.observe(Some("Disconnected"), s(2, t0));
        assert!(p.blocking(s(2, t0)), "kill switch not restored: guard blocks on disconnect");
        assert!(p.reason(s(2, t0)).contains("isn't back"));
        p.set_strict(false);
        assert!(!p.blocking(s(3, t0)), "back to the normal hand-off once restored");
    }

    #[test]
    fn auto_connect_once_per_boot_or_wake() {
        let t0 = Instant::now();
        let mut p = Policy::new(BlockMode::Startup, true, t0);
        assert!(!p.should_auto_connect(s(1, t0)), "state not known yet");
        p.observe(Some("Disconnected"), s(2, t0));
        assert!(p.should_auto_connect(s(2, t0)));
        assert!(!p.should_auto_connect(s(3, t0)), "only once");
        p.rearm(s(50, t0), "woke up");
        p.observe(Some("Disconnected"), s(51, t0));
        assert!(p.should_auto_connect(s(51, t0)), "again after wake");
        // after the VPN was connected once, a Disconnect is the user's choice
        let mut r = Policy::new(BlockMode::Always, true, t0);
        r.observe(Some("Connected"), s(1, t0));
        r.observe(Some("Disconnected"), s(30, t0));
        assert!(!r.should_auto_connect(s(30, t0)), "no reconnect behind the user's back");
        let mut q = Policy::new(BlockMode::Off, true, t0);
        q.observe(Some("Disconnected"), s(1, t0));
        assert!(!q.should_auto_connect(s(1, t0)), "never when the block is off");
    }

    #[test]
    fn stuck_connecting_gets_a_bounded_nudge() {
        let t0 = Instant::now();
        let mut p = Policy::new(BlockMode::Startup, false, t0);
        let mut t = 0;
        p.observe(Some("Connecting"), s(0, t0));
        // keep reporting Connecting (fresh observations, same state)
        let mut kicks = vec![];
        while t < 400 {
            t += 5;
            p.observe(Some("Connecting"), s(t, t0));
            if p.should_kick(s(t, t0)) {
                kicks.push(t);
            }
        }
        assert_eq!(kicks, vec![90, 180], "after 90 s, again 90 s later, then no more");
        assert!(p.blocking(s(t, t0)), "never lifts the block");
        // connected -> handed off -> no nudging
        p.observe(Some("Connected"), s(401, t0));
        p.rearm(s(500, t0), "woke up");
        assert_eq!(p.kicks(), 0, "budget resets after wake");
        let mut q = Policy::new(BlockMode::Startup, false, t0);
        q.observe(Some("Connected"), s(1, t0));
        q.observe(Some("Connecting"), s(2, t0));
        assert!(!q.should_kick(s(200, t0)), "not after the hand-off (PIA's own business)");
    }

    #[test]
    fn mode_off_never_blocks_and_switching_on_while_connected_stays_open() {
        let t0 = Instant::now();
        let mut p = Policy::new(BlockMode::Off, false, t0);
        connect(&mut p, s(1, t0));
        assert!(!p.blocking(s(1, t0)));
        p.set_mode(BlockMode::Startup);
        assert!(!p.blocking(s(2, t0)), "already connected since start -> handed off");
        p.set_mode(BlockMode::Always);
        assert!(!p.blocking(s(2, t0)));
    }

    /// Review V64-01: PIA's service being briefly unreachable (None) is not
    /// a disconnect - it must not end the user's Disconnect; nor does a
    /// disconnect that never happened (piactl failed, PIA stays Connected).
    #[test]
    fn an_unreachable_moment_does_not_end_the_users_disconnect() {
        let t0 = Instant::now();
        let mut p = Policy::new(BlockMode::Always, true, t0);
        p.observe(Some("Connected"), s(1, t0));
        p.note_user(true);
        p.observe(None, s(2, t0));
        p.observe(Some("Connected"), s(3, t0));
        assert!(p.user_off(), "Connected -> unknown -> Connected: the same connection");
        p.observe(Some("Disconnecting"), s(4, t0));
        p.observe(Some("Connected"), s(5, t0));
        assert!(p.user_off(), "never seen Disconnected: no new connection proven");
        // the user's piactl disconnect failed: PIA stays Connected - the choice stays
        let mut p = Policy::new(BlockMode::Always, true, t0);
        p.observe(Some("Connected"), s(1, t0));
        p.note_user(true);
        for n in 2..6 {
            p.observe(Some("Connected"), s(n, t0));
        }
        assert!(p.user_off());
        // control: really disconnected, then a new connection
        p.observe(Some("Disconnected"), s(6, t0));
        p.observe(Some("Connecting"), s(7, t0));
        p.observe(Some("Connected"), s(8, t0));
        assert!(!p.user_off());
    }

    /// Review FINAL-02: after the user presses Disconnect in the tray the
    /// guard neither connects at startup/wake nor restarts an attempt, until
    /// they connect again, PIA is seen connected, or the next boot/wake.
    #[test]
    fn a_user_disconnect_stops_automatic_connects() {
        let t0 = Instant::now();
        let s = |n: u64| t0 + Duration::from_secs(n);
        let fresh = |user_off: bool| {
            let mut p = Policy::new(BlockMode::Always, true, t0);
            p.set_network(Some(true), t0);
            p.observe(Some("Disconnected"), s(1));
            p.note_user(user_off);
            p
        };
        assert!(fresh(false).should_auto_connect(s(1)), "control: it would connect");
        let mut p = fresh(true);
        assert!(!p.should_auto_connect(s(1)), "not against the user");
        p.observe(Some("Connecting"), s(2));
        let gen = p.attempt_gen();
        assert!(!p.kick_still_valid(gen, s(2)) && !p.should_kick(s(200)), "no restarts either");
        p.note_user(false);
        assert!(!p.kick_still_valid(gen, s(3)), "a restart decided before the user's Connect is stale");
        let gen = p.attempt_gen();
        assert!(p.kick_still_valid(gen, s(3)), "after Connect in the tray: back to normal");
        // V65-03: a "Disconnected" from BEFORE the press doesn't count (it may be
        // stale); only one reported after it, followed by a connection
        let mut p = fresh(true);
        p.observe(Some("Connecting"), s(2));
        p.observe(Some("Connected"), s(3));
        assert!(p.user_off(), "no Disconnected seen after the press: still the user's choice");
        p.observe(Some("Disconnected"), s(4));
        p.observe(Some("Connecting"), s(5));
        p.observe(Some("Connected"), s(6));
        assert!(!p.user_off(), "a new connection after a reported disconnect: the user's off is over");
        // V63-02: Disconnect pressed while PIA still reports Connected
        let mut p = Policy::new(BlockMode::Always, true, t0);
        p.observe(Some("Connected"), s(1));
        p.note_user(true);
        p.observe(Some("Connected"), s(2));
        p.observe(Some("Connected"), s(3));
        assert!(p.user_off(), "more 'Connected' reports from before the disconnect took don't end it");
        p.observe(Some("Disconnected"), s(4));
        assert!(p.user_off());
        p.observe(Some("Connecting"), s(5));
        let gen = p.attempt_gen();
        assert!(!p.kick_still_valid(gen, s(5)), "still no restarts");
        p.observe(Some("Connected"), s(6));
        assert!(!p.user_off(), "a genuine later connection ends it");
        // a user command makes any restart decided before it stale
        let mut p = Policy::new(BlockMode::Always, true, t0);
        p.observe(Some("Connecting"), s(1));
        let gen = p.attempt_gen();
        p.note_user(false);
        assert!(!p.kick_still_valid(gen, s(1)), "decided before the user's Connect");
        let mut p = fresh(true);
        let _ = p.rearm(s(4), "wake");
        assert!(!p.user_off(), "a new boot/wake starts fresh");
    }
}
