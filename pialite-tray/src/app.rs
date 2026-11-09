//! App state and wiring: piactl monitors -> state -> tray icon / menu / popup panel.
//! Everything UI-related runs on the Slint event-loop thread; worker threads only
//! send updates with `post()`.

use std::cell::RefCell;
use std::time::{Duration, Instant};

use slint::winit_030::{winit, EventResult, WinitWindowAccessor};
use slint::{ComponentHandle, Image, ModelRc, Rgba8Pixel, SharedPixelBuffer, VecModel};

use crate::{guard, icons, piactl, regions, winutil, Features, Popup, RegionEntry, Tray};

#[derive(Default)]
struct State {
    conn: Option<String>,   // piactl connectionstate; None = PIA service not reachable
    region: Option<String>, // selected region id ("auto" or e.g. "us-east")
    vpnip: Option<String>,
    regions: Vec<String>,
    regions_rev: u64, // bumped whenever the region list's content changes
    filter: String,
    autostart: bool,
    // A connect/disconnect/region command is running. Only that command's own
    // completion clears it - not status events (audit P3-26).
    pending: Option<u64>,
    next_op: u64,
    connect_on_start: bool,       // follow PIA's own "Connect on launch" setting once at startup
    guard: Option<guard::Status>, // None = guard service not reachable
    guard_polled: bool,
    notice: Option<(String, Instant)>, // short-lived error from a command, shown in menu/panel
    update: Option<guard::Update>,     // a newer release (checked about once a day)
    install: Option<guard::Install>,   // what the installer set up (install.json)
}

/// PIA's own "Connect on launch" setting, read as JSON (audit P3-25).
fn parse_connect_on_launch(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text).ok().and_then(|v| v.get("connectOnLaunch").and_then(|x| x.as_bool())).unwrap_or(false)
}

fn pia_connect_on_launch() -> bool {
    #[cfg(windows)]
    let path =
        std::env::var_os("LOCALAPPDATA").map(|b| std::path::PathBuf::from(b).join("Private Internet Access").join("clientsettings.json"));
    // PIA's Linux client keeps it in ~/.config/privateinternetaccess
    #[cfg(not(windows))]
    let path = std::env::var_os("HOME")
        .map(|h| std::path::PathBuf::from(h).join(".config").join("privateinternetaccess").join("clientsettings.json"));
    path.and_then(|p| std::fs::read_to_string(p).ok()).map(|t| parse_connect_on_launch(&t)).unwrap_or(false)
}

struct App {
    tray: Tray,
    popup: Option<Popup>,
    features: Option<Features>,
    st: State,
    light_taskbar: bool,
    icon_kind: Option<icons::Kind>,
    menu_key: String,
    list_key: String,
    popup_closed_at: Option<Instant>,
}

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
}

// ------------------------------------------------------------------ logging

pub fn log(msg: &str) {
    pialite_common::logfile::append(&log_dir().join("tray.log"), 256 * 1024, msg);
}

fn log_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    let base = std::env::var_os("LOCALAPPDATA").map(std::path::PathBuf::from);
    #[cfg(not(windows))]
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".local").join("state")));
    base.unwrap_or_else(std::env::temp_dir).join(if cfg!(windows) { "PiaLite" } else { "pialite" })
}

/// Which optional parts to show: what the running guard says, else what
/// the installer recorded, else everything (an older install).
fn shown(st: &State, feature: &str) -> bool {
    match (&st.guard, &st.install) {
        (Some(g), _) => feature == "guard" || guard::has_feature(g, feature),
        (None, Some(i)) => i.features.iter().any(|f| f == feature),
        (None, None) => true,
    }
}

// ------------------------------------------------------------------ helpers

fn with_app(f: impl FnOnce(&mut App)) {
    APP.with(|cell| match cell.try_borrow_mut() {
        Ok(mut guard) => {
            if let Some(app) = guard.as_mut() {
                f(app);
            }
        }
        Err(_) => log("internal: app state busy, update skipped"),
    });
}

/// Send an update from any thread to the UI thread, then refresh the UI.
fn post(f: impl FnOnce(&mut App) + Send + 'static) {
    let _ = slint::invoke_from_event_loop(move || {
        with_app(|app| {
            f(app);
            app.refresh();
        })
    });
}

fn icon_image(kind: icons::Kind, light: bool) -> Image {
    let px = icons::render(kind, light);
    Image::from_rgba8(SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(&px, icons::SIZE, icons::SIZE))
}

fn entries(ids: &[String], current: Option<&str>) -> ModelRc<RegionEntry> {
    let rows: Vec<RegionEntry> = ids
        .iter()
        .map(|id| {
            let cur = current == Some(id.as_str());
            let label = format!("{}{}", if cur { "\u{2713} " } else { "" }, regions::pretty(id));
            RegionEntry { id: id.as_str().into(), label: label.into(), current: cur }
        })
        .collect();
    ModelRc::new(VecModel::from(rows))
}

// ------------------------------------------------------------------ refresh

impl App {
    fn refresh(&mut self) {
        let st = &self.st;
        let hotel = st.guard.as_ref().is_some_and(|g| g.hotel);
        let kind = if hotel { icons::Kind::Busy } else { icons::Kind::from_state(st.conn.as_deref()) };
        if self.icon_kind != Some(kind) {
            self.tray.set_status_icon(icon_image(kind, self.light_taskbar));
            self.icon_kind = Some(kind);
        }

        let header = if hotel { "HOTEL WI-FI LOGIN".to_string() } else { piactl::header_text(st.conn.as_deref()).to_string() };
        let region_label = st.region.as_deref().map(regions::pretty).unwrap_or_else(|| "-".into());
        let ip = st.vpnip.clone().filter(|v| v != "Unknown" && !v.is_empty()).unwrap_or_else(|| "-".into());
        let connected = st.conn.as_deref() == Some("Connected");
        let disconnected = st.conn.as_deref() == Some("Disconnected");

        let busy = st.pending.is_some();
        let mut tip = format!("PIA: {}", st.conn.as_deref().unwrap_or("service not running"));
        if connected {
            tip.push_str(&format!("\n{region_label}  {ip}"));
        }
        self.tray.set_status_tooltip(tip.into());
        self.tray.set_status_line(format!("{header}  -  {region_label}").into());
        self.tray.set_can_connect(disconnected && !busy);
        self.tray.set_can_disconnect(st.conn.is_some() && !disconnected && !busy);
        let start_label = if cfg!(windows) { "Start with Windows" } else { "Start when I sign in" };
        self.tray.set_autostart_title(if st.autostart { format!("\u{2713} {start_label}") } else { start_label.to_string() }.into());
        self.tray.set_hotel_feature(shown(st, "hotel"));
        self.tray.set_block_feature(shown(st, "guard"));
        self.tray.set_update_available(st.update.is_some());
        if let Some(u) = &st.update {
            self.tray.set_update_title(
                if u.one_click {
                    format!("Install update {} (restarts PIA Lite)", u.latest)
                } else {
                    format!("Update {} available - open download page", u.latest)
                }
                .into(),
            );
        }

        // guard service (DNS proxy / startup block / hotel login)
        let (mut gtext, mut gwarn) = if st.guard_polled {
            guard::summary(st.guard.as_ref(), st.conn.as_deref())
        } else {
            ("Checking guard service...".to_string(), false)
        };
        if let Some((msg, at)) = &st.notice {
            if at.elapsed() < Duration::from_secs(10) {
                (gtext, gwarn) = (msg.clone(), true);
            }
        }
        let g = st.guard.as_ref();
        let hotel_label = match g {
            Some(g) if g.hotel => format!("End hotel login now ({} left)", guard::mmss(g.hotel_left)),
            Some(g) => format!("Hotel Wi-Fi login (VPN off for {} min)", g.hotel_minutes),
            None => "Hotel Wi-Fi login".to_string(),
        };
        let mode = g.map(|g| g.mode);
        let tick = |m: guard::BlockMode| -> slint::SharedString {
            let mark = if mode == Some(m) { "\u{2713} " } else { "" };
            format!("{mark}{}", guard::mode_label(m)).into()
        };
        self.tray.set_guard_available(g.is_some());
        self.tray.set_guard_line(gtext.clone().into());
        self.tray.set_hotel_title(hotel_label.clone().into());
        self.tray.set_block_off_title(tick(guard::BlockMode::Off));
        self.tray.set_block_startup_title(tick(guard::BlockMode::Startup));
        self.tray.set_block_always_title(tick(guard::BlockMode::Always));

        // tray region menus: rebuilt only when the list or the selected region changes
        let key = format!("{:?}|{}", st.region, st.regions_rev);
        if key != self.menu_key {
            self.menu_key = key;
            let cur = st.region.as_deref();
            let g = regions::group(&st.regions);
            self.tray.set_auto_title(if cur == Some("auto") { "\u{2713} Auto (fastest)" } else { "Auto (fastest)" }.into());
            self.tray.set_regions_us(entries(&g.us, cur));
            self.tray.set_regions_ca(entries(&g.ca, cur));
            self.tray.set_regions_streaming(entries(&g.streaming, cur));
            self.tray.set_regions_other_a(entries(&g.other_a, cur));
            self.tray.set_regions_other_b(entries(&g.other_b, cur));
        }

        // popup panel (only exists while open)
        if let Some(p) = &self.popup {
            p.set_header_text(header.into());
            p.set_kind(kind as i32);
            p.set_region_label(region_label.into());
            p.set_vpn_ip(ip.into());
            p.set_busy(busy || st.conn.is_none());
            let hint = match st.conn.as_deref() {
                None => "Waiting for PIA's background service...",
                _ if busy => "Working...",
                Some("Connected") => "Click to disconnect",
                Some("Disconnected") => "Click to connect",
                Some(_) => "Click to cancel",
            };
            p.set_hint_text(if hotel { "Log in on the hotel page, then the VPN comes back" } else { hint }.into());
            p.set_guard_text(gtext.into());
            p.set_guard_warn(gwarn);
            p.set_hotel_label(hotel_label.into());
            p.set_hotel_enabled(g.is_some());
            p.set_hotel_feature(shown(st, "hotel"));
            p.set_update_text(
                st.update.as_ref().map(|u| format!("Update available: {} - click to install", u.latest)).unwrap_or_default().into(),
            );
            let list_key = format!("{:?}|{}|{}", st.region, st.regions_rev, st.filter);
            if list_key != self.list_key {
                self.list_key = list_key;
                let mut ids = vec!["auto".to_string()];
                ids.extend(regions::filtered(&st.regions, &st.filter));
                if !st.filter.trim().is_empty() && !"auto (fastest)".contains(&st.filter.trim().to_lowercase()) {
                    ids.remove(0);
                }
                p.set_region_list(entries(&ids, st.region.as_deref()));
            }
        }
    }
}

// ------------------------------------------------------------------ actions

static FETCHING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static FETCH_AGAIN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Read PIA's region and VPN IP once, on a worker thread (at most one at a time).
fn refresh_details() {
    use std::sync::atomic::Ordering::SeqCst;
    FETCH_AGAIN.store(true, SeqCst);
    if FETCHING.swap(true, SeqCst) {
        return; // the running fetch will go round again
    }
    std::thread::spawn(|| {
        while FETCH_AGAIN.swap(false, SeqCst) && !piactl::is_shutdown() {
            std::thread::sleep(Duration::from_millis(800)); // let PIA settle after a change
            let region = piactl::run(&["get", "region"]).ok();
            let vpnip = piactl::run(&["get", "vpnip"]).ok();
            post(move |app| {
                app.st.region = region;
                app.st.vpnip = vpnip;
            });
        }
        FETCHING.store(false, SeqCst);
        if FETCH_AGAIN.load(SeqCst) {
            refresh_details();
        }
    });
}

/// Mark a command as running; returns its id.
fn begin_op(app: &mut App) -> u64 {
    app.st.next_op += 1;
    app.st.pending = Some(app.st.next_op);
    app.st.next_op
}

/// Run piactl commands in order on a worker thread. When they finish (or one
/// fails or times out) the busy state is cleared and any error is shown.
/// A step whose first word is this goes to the guard, not to piactl.
const GUARD_STEP: &str = "@guard";
/// The same, when no guard seems installed: tried, but a failure is normal.
const GUARD_STEP_QUIET: &str = "@guard?";

/// Run the steps IN ORDER (review V63-03): a note to the guard first, then
/// PIA's command. A note that doesn't arrive is retried once and then
/// reported (`warning`), but never stops PIA's command - Disconnect must work
/// without the guard. A failing piactl step stops the rest (`error`).
fn run_steps(
    steps: &[Vec<String>],
    piactl: &mut dyn FnMut(&[&str]) -> Result<(), String>,
    guard: &mut dyn FnMut(&str) -> Result<(), String>,
) -> (Option<String>, Option<String>) {
    let (mut error, mut warning) = (None, None);
    for step in steps {
        let first = step.first().map(String::as_str);
        if first == Some(GUARD_STEP) || first == Some(GUARD_STEP_QUIET) {
            let note = step[1..].join(" ");
            if let Err(e) = guard(&note).or_else(|_| guard(&note)) {
                if first == Some(GUARD_STEP) {
                    warning = Some(format!("the guard didn't get '{note}' ({e}) - it may connect on its own"));
                }
            }
            continue;
        }
        let args: Vec<&str> = step.iter().map(String::as_str).collect();
        if let Err(e) = piactl(&args) {
            error = Some(e);
            break;
        }
    }
    (error, warning)
}

fn run_piactl_steps(op: u64, steps: Vec<Vec<String>>) {
    std::thread::spawn(move || {
        let (error, warning) = run_steps(&steps, &mut |a| piactl::run(a).map(|_| ()), &mut |note| {
            pialite_common::ipc::request_within(note, Duration::from_secs(2)).map(|_| ())
        });
        for m in error.iter().chain(warning.iter()) {
            log(m);
        }
        refresh_details();
        post(move |app| {
            if app.st.pending == Some(op) {
                app.st.pending = None;
            }
            if let Some(e) = error {
                app.st.notice = Some((format!("PIA: {}", e.chars().take(80).collect::<String>()), Instant::now()));
            } else if let Some(w) = warning {
                app.st.notice = Some((format!("Guard: {}", w.chars().take(80).collect::<String>()), Instant::now()));
            }
        });
    });
}

fn start(steps: Vec<Vec<String>>) {
    let mut op = 0;
    with_app(|app| {
        if app.st.pending.is_none() {
            op = begin_op(app);
            app.refresh();
        }
    });
    if op != 0 {
        run_piactl_steps(op, steps);
    }
}

/// The user's Connect/Disconnect: first tell the guard (so it never connects
/// against a Disconnect pressed here - review FINAL-02, V63-03), then PIA -
/// on one worker, in that order. Without a guard there is no one to tell.
fn user_command(cmd: &str) {
    // Always tried - the tray's cached guard status can be missing or old
    // (it is polled every few seconds) while the guard runs (review V64-03).
    // Only when no guard is installed is a failed note normal and silent;
    // an absent pipe fails at once, so that costs no waiting.
    // V65-04: "installed" = the service is registered (wherever its program
    // is), not only "the program file is where it used to be"
    let mut seen = false;
    with_app(|app| seen = app.st.guard.is_some());
    let expected = seen || winutil::guard_service_registered() || guard::guard_exe().is_file();
    let kind = if expected { GUARD_STEP } else { GUARD_STEP_QUIET };
    start(vec![vec![kind.to_string(), "user".into(), cmd.into()], vec![cmd.to_string()]]);
}

fn connect() {
    user_command("connect");
}

fn disconnect() {
    user_command("disconnect");
}

fn toggle_connect() {
    let mut want_connect = false;
    with_app(|app| want_connect = app.st.conn.as_deref() == Some("Disconnected"));
    if want_connect {
        connect()
    } else {
        disconnect()
    }
}

fn pick_region(id: String) {
    let mut steps = vec![vec!["set".to_string(), "region".to_string(), id]];
    with_app(|app| {
        // PIA applies a new region on the next connect, so reconnect if we're not disconnected
        if app.st.conn.as_deref().is_some_and(|c| c != "Disconnected") {
            steps.push(vec!["connect".into()]);
        }
    });
    start(steps);
}

fn toggle_autostart() {
    with_app(|app| {
        let want = !app.st.autostart;
        match winutil::set_autostart(want) {
            Ok(()) => app.st.autostart = want,
            Err(e) => log(&e),
        }
        app.refresh();
    });
}

/// Run a guard command off the UI thread; show its result briefly if it failed.
fn guard_command(cmd: String, then: Option<fn()>) {
    guard_task(cmd.clone(), move || guard::request(&cmd).map(|_| ()), then);
}

/// A guard command that weakens protection (block down/off, hotel login):
/// Windows asks "Run as administrator?" first (review N-04).
fn guard_command_admin(args: &'static [&'static str], then: Option<fn()>) {
    guard_task(args.join(" "), move || winutil::run_elevated(args), then);
}

fn guard_task(cmd: String, run: impl FnOnce() -> Result<(), String> + Send + 'static, then: Option<fn()>) {
    std::thread::spawn(move || {
        let r = run();
        if let Err(e) = &r {
            log(&format!("guard {cmd}: {e}"));
        }
        let status = guard::status();
        if r.is_ok() {
            if let Some(f) = then {
                f();
            }
        }
        post(move |app| {
            app.st.guard = status;
            app.st.guard_polled = true;
            app.st.notice = r.err().map(|e| (format!("Failed: {e}"), Instant::now()));
        });
    });
}

fn set_block_mode(mode: String) {
    let Some(new) = guard::BlockMode::parse(&mode) else { return };
    let mut current = None;
    with_app(|app| current = app.st.guard.as_ref().map(|g| g.mode));
    if current.is_some_and(|c| new.weaker_than(c)) {
        guard_command_admin(
            match new {
                guard::BlockMode::Off => &["mode", "off"],
                guard::BlockMode::Startup => &["mode", "startup"],
                guard::BlockMode::Always => &["mode", "always"],
            },
            None,
        );
    } else {
        guard_command(format!("mode {mode}"), None);
    }
}

fn toggle_hotel() {
    let mut active = false;
    with_app(|app| active = app.st.guard.as_ref().is_some_and(|g| g.hotel));
    if active {
        guard_command("hotel stop".into(), None);
    } else {
        // Once the VPN is off, open a plain-http page so the hotel's login
        // page can take over (Windows often pops it up by itself too).
        guard_command_admin(
            &["hotel", "start"],
            Some(|| {
                std::thread::sleep(Duration::from_secs(3));
                winutil::open_url("http://neverssl.com");
            }),
        );
    }
}

// ------------------------------------------------------------------ updates

/// "Install update": the guard program downloads the package for this kind
/// of install, checks its signature and installs it (asks for admin).
fn do_update() {
    let mut u = None;
    with_app(|app| u = app.st.update.clone());
    let Some(u) = u else { return };
    if !u.one_click {
        winutil::open_url(&u.page);
        return;
    }
    with_app(|app| {
        app.st.notice = Some((format!("Installing PIA Lite {}...", u.latest), Instant::now()));
        app.refresh();
    });
    guard_task("apply-update".into(), || winutil::run_elevated(&["apply-update"]), Some(after_update));
}

fn after_update() {
    log("update installed - restarting");
    piactl::shutdown();
    // Windows: the updater replaces the files and starts the tray again;
    // Linux: the package is already replaced - start the new program
    let _ = slint::invoke_from_event_loop(|| {
        if cfg!(windows) {
            let _ = slint::quit_event_loop();
        } else {
            winutil::restart_self();
        }
    });
}

fn start_update_checks() {
    if std::env::var_os("PIALITE_NO_UPDATE_CHECK").is_some() {
        return;
    }
    std::thread::spawn(|| {
        std::thread::sleep(Duration::from_secs(90)); // not while signing in
        while !piactl::is_shutdown() {
            if let Some(u) = guard::check_update() {
                log(&format!("update available: PIA Lite {}", u.latest));
                post(move |app| app.st.update = Some(u));
            }
            // about once a day
            for _ in 0..(24 * 60) {
                if piactl::is_shutdown() {
                    return;
                }
                std::thread::sleep(Duration::from_secs(60));
            }
        }
    });
}

// ------------------------------------------------------------------ features window

const PROVIDERS: [&str; 5] = ["quad9", "cloudflare", "adguard", "google", "nextdns"];
const MODES: [&str; 3] = ["off", "startup", "always"];

/// Choose / change the installed features. MSI installs use the MSI's own
/// "Change" screen (Windows' installer stays the one place that knows).
fn open_features() {
    let mut msi = None;
    with_app(|app| {
        app.st.install = guard::install_record();
        msi = app.st.install.as_ref().filter(|i| i.kind == "msi" && !i.product_code.is_empty()).map(|i| i.product_code.clone());
    });
    if let Some(code) = msi {
        if let Err(e) = std::process::Command::new("msiexec").args(["/i", &code]).spawn() {
            log(&format!("could not open the installer: {e}"));
        }
        return;
    }
    with_app(|app| {
        if let Some(w) = &app.features {
            let _ = w.show();
            return;
        }
        let w = match Features::new() {
            Ok(w) => w,
            Err(e) => {
                log(&format!("could not open the features window: {e}"));
                return;
            }
        };
        let fresh = app.st.install.is_none();
        let f = app.st.install.as_ref().map(|i| i.features.clone()).unwrap_or_default();
        let on = |n: &str| fresh || f.iter().any(|x| x == n);
        w.set_guard(on("guard"));
        w.set_dns(on("dns"));
        w.set_hotel(on("hotel"));
        w.set_autostart(fresh || app.st.autostart);
        let provider = app.st.guard.as_ref().map(|g| g.dns_provider.clone()).unwrap_or_default();
        w.set_provider(PROVIDERS.iter().position(|p| *p == provider).unwrap_or(0) as i32);
        let mode = app.st.guard.as_ref().map(|g| g.mode.as_str().to_string()).unwrap_or_else(|| "startup".into());
        w.set_mode(MODES.iter().position(|m| *m == mode).unwrap_or(1) as i32);
        w.set_apply_label(if cfg!(windows) { "Apply (asks for admin)" } else { "Apply (asks for your password)" }.into());
        if fresh {
            w.set_status_text("First start: choose what you want, then Apply. You can change it later from the tray menu.".into());
        }
        w.on_apply(apply_features);
        w.on_cancel(close_features);
        if let Err(e) = w.show() {
            log(&format!("could not show the features window: {e}"));
            return;
        }
        app.features = Some(w);
    });
}

fn close_features() {
    with_app(|app| {
        if let Some(w) = app.features.take() {
            let _ = w.hide();
            slint::Timer::single_shot(Duration::from_millis(50), move || drop(w));
        }
    });
}

/// The setup command line for the choices in the window (only fixed words
/// and a checked profile ID - see guard::safe_arg).
/// What the features window shows.
#[derive(Default)]
struct Choices {
    guard: bool,
    dns: bool,
    hotel: bool,
    autostart: bool,
    provider: usize,
    nextdns_id: String,
    mode: usize,
}

fn setup_args(c: &Choices, me: &str) -> Result<Vec<String>, String> {
    let Choices { guard: guard_on, dns, hotel, autostart, provider, ref nextdns_id, mode } = *c;
    let mut feats = vec![];
    if guard_on {
        feats.push("guard");
        if dns {
            feats.push("dns");
        }
        if hotel {
            feats.push("hotel");
        }
    }
    if autostart {
        feats.push("autostart");
    }
    let mut a: Vec<String> = vec!["setup".into(), "--features".into(), if feats.is_empty() { "none".into() } else { feats.join(",") }];
    if guard_on {
        a.extend(["--mode".into(), MODES[mode.min(2)].into()]);
    }
    if guard_on && dns {
        let p = PROVIDERS[provider.min(PROVIDERS.len() - 1)];
        a.extend(["--dns".into(), p.into()]);
        if p == "nextdns" {
            let id = nextdns_id.trim();
            if id.len() < 4 || id.len() > 12 || !id.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err("Enter your NextDNS profile ID (letters and numbers, from my.nextdns.io) - or pick another provider.".into());
            }
            a.extend(["--nextdns-id".into(), id.into()]);
        }
    }
    if guard::safe_arg(me) {
        a.extend(["--user".into(), me.into()]);
    }
    Ok(a)
}

fn apply_features() {
    let mut args = None;
    with_app(|app| {
        let Some(w) = &app.features else { return };
        let c = Choices {
            guard: w.get_guard(),
            dns: w.get_dns(),
            hotel: w.get_hotel(),
            autostart: w.get_autostart(),
            provider: w.get_provider().max(0) as usize,
            nextdns_id: w.get_nextdns_id().to_string(),
            mode: w.get_mode().max(0) as usize,
        };
        match setup_args(&c, &winutil::my_user_id()) {
            Ok(a) => {
                w.set_busy(true);
                w.set_status_warn(false);
                w.set_status_text("Applying - this can take half a minute...".into());
                args = Some(a);
            }
            Err(e) => {
                w.set_status_warn(true);
                w.set_status_text(e.into());
            }
        }
    });
    let Some(args) = args else { return };
    std::thread::spawn(move || {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let r = winutil::run_elevated(&refs);
        if let Err(e) = &r {
            log(&format!("setup from the features window: {e}"));
        }
        let status = guard::status();
        post(move |app| {
            app.st.install = guard::install_record();
            app.st.autostart = winutil::autostart_enabled();
            app.st.guard = status;
            app.st.guard_polled = true;
            match r {
                Ok(()) => {
                    app.st.notice = Some(("Features saved".into(), Instant::now()));
                    if let Some(w) = app.features.take() {
                        let _ = w.hide();
                        slint::Timer::single_shot(Duration::from_millis(50), move || drop(w));
                    }
                }
                Err(e) => {
                    if let Some(w) = &app.features {
                        w.set_busy(false);
                        w.set_status_warn(true);
                        w.set_status_text(e.chars().take(300).collect::<String>().into());
                    }
                }
            }
        });
    });
}

// ------------------------------------------------------------------ popup panel

fn hide_popup() {
    with_app(|app| {
        if let Some(p) = app.popup.take() {
            let _ = p.hide();
            app.popup_closed_at = Some(Instant::now());
            app.st.filter.clear();
            // Drop it a moment later (not inside its own event) so its memory is released.
            slint::Timer::single_shot(Duration::from_millis(50), move || drop(p));
        }
    });
}

fn hide_popup_later() {
    let _ = slint::invoke_from_event_loop(hide_popup);
}

fn wire_popup(p: &Popup) {
    p.on_toggle_connect(toggle_connect);
    p.on_pick_region(|id| pick_region(id.to_string()));
    p.on_filter_changed(|text| {
        with_app(|app| {
            app.st.filter = text.to_string();
            app.refresh();
        })
    });
    p.on_open_pia(|| {
        winutil::open_pia();
        hide_popup_later();
    });
    p.on_close_panel(hide_popup_later);
    p.on_toggle_hotel(toggle_hotel);
    p.on_do_update(|| {
        hide_popup_later();
        do_update();
    });
    // Close when you click anywhere else, like PIA's own popup.
    p.window().on_winit_window_event(|_w, event| {
        if let winit::event::WindowEvent::Focused(false) = event {
            hide_popup_later();
        }
        EventResult::Propagate
    });
}

fn place_popup(p: &Popup, width: i32, height: i32) {
    #[cfg(not(windows))]
    {
        // top-right of the screen it opens on, below a top bar
        let mon = p
            .window()
            .with_winit_window(|w| w.current_monitor().or_else(|| w.primary_monitor()).map(|m| (m.position(), m.size())))
            .flatten();
        if let Some((pos, size)) = mon {
            p.window().set_position(slint::PhysicalPosition::new(pos.x + size.width as i32 - width - 12, pos.y + 48));
            return;
        }
    }
    let (_left, _top, right, bottom) = winutil::work_area();
    let margin = (10.0 * winutil::system_scale()) as i32;
    p.window().set_position(slint::PhysicalPosition::new(right - width - margin, bottom - height - margin));
}

fn toggle_popup() {
    let mut open_new = false;
    with_app(|app| {
        if app.popup.is_some() {
            return; // handled below (hide)
        }
        // A click on the tray icon while the panel was open already closed it via focus loss.
        if app.popup_closed_at.is_some_and(|t| t.elapsed() < Duration::from_millis(400)) {
            return;
        }
        open_new = true;
    });

    let mut is_open = false;
    with_app(|app| is_open = app.popup.is_some());
    if is_open {
        hide_popup();
        return;
    }
    if !open_new {
        return;
    }

    let p = match Popup::new() {
        Ok(p) => p,
        Err(e) => {
            log(&format!("could not create panel: {e}"));
            return;
        }
    };
    wire_popup(&p);
    let scale = winutil::system_scale();
    place_popup(&p, (320.0 * scale) as i32, (500.0 * scale) as i32);
    if let Err(e) = p.show() {
        log(&format!("could not show panel: {e}"));
        return;
    }
    let weak = p.as_weak();
    with_app(|app| {
        app.popup = Some(p);
        app.list_key.clear();
        app.refresh();
    });
    // Once the window really exists: fix the position using its real size and give it focus.
    slint::Timer::single_shot(Duration::from_millis(40), move || {
        if let Some(p) = weak.upgrade() {
            let size = p.window().size();
            place_popup(&p, size.width as i32, size.height as i32);
            p.window().with_winit_window(|w| w.focus_window());
        }
    });
}

// ------------------------------------------------------------------ startup

fn select_backend() -> Result<(), String> {
    let selector = slint::BackendSelector::new().backend_name("winit".into()).renderer_name("software".into());
    #[cfg(windows)]
    let selector = selector.with_winit_window_attributes_hook(|attrs| {
        use winit::platform::windows::WindowAttributesExtWindows;
        attrs.with_skip_taskbar(true) // the panel never shows up in the taskbar
    });
    selector.select().map_err(|e| format!("could not start UI: {e}"))
}

fn wire_tray(t: &Tray) {
    t.on_show_panel(toggle_popup);
    t.on_do_connect(connect);
    t.on_do_disconnect(disconnect);
    t.on_pick_region(|id| pick_region(id.to_string()));
    t.on_open_pia(winutil::open_pia);
    t.on_toggle_autostart(toggle_autostart);
    t.on_set_block_mode(|m| set_block_mode(m.to_string()));
    t.on_toggle_hotel(toggle_hotel);
    t.on_do_update(do_update);
    t.on_open_features(open_features);
    t.on_quit(|| {
        let _ = slint::quit_event_loop();
    });
}

fn start_workers() {
    piactl::monitor("connectionstate", |v| {
        post(move |app| {
            // First status after startup: connect if PIA's "Connect on launch" is on.
            if app.st.connect_on_start && v.is_some() {
                app.st.connect_on_start = false;
                if v.as_deref() == Some("Disconnected") && app.st.pending.is_none() {
                    log("connecting at startup (PIA 'Connect on launch' is on)");
                    let op = begin_op(app);
                    run_piactl_steps(op, vec![vec!["connect".into()]]);
                }
            }
            let changed = app.st.conn != v;
            app.st.conn = v;
            if changed {
                refresh_details();
            }
        })
    });
    // Region + VPN IP: read when the connection state changes, after a
    // command, and once a minute - instead of two more `piactl monitor`
    // processes running all the time (~10 MB each, measured in Phase 5; review N-16).
    std::thread::spawn(|| {
        while !piactl::is_shutdown() {
            refresh_details();
            std::thread::sleep(Duration::from_secs(60));
        }
    });
    // Guard service status: every 4 s (every 2 s during hotel login, for the countdown).
    std::thread::spawn(|| {
        while !piactl::is_shutdown() {
            let status = guard::status();
            let fast = status.as_ref().is_some_and(|g| g.hotel);
            post(move |app| {
                app.st.guard = status;
                app.st.guard_polled = true;
            });
            std::thread::sleep(Duration::from_secs(if fast { 2 } else { 4 }));
        }
    });
    // The region list rarely changes: fetch it once (retry until PIA's service answers).
    std::thread::spawn(|| {
        while !piactl::is_shutdown() {
            match piactl::run(&["get", "regions"]) {
                Ok(text) => {
                    let list = regions::parse_list(&text);
                    if !list.is_empty() {
                        post(move |app| {
                            if app.st.regions != list {
                                app.st.regions = list;
                                app.st.regions_rev += 1;
                            }
                        });
                        return;
                    }
                }
                Err(e) => log(&e),
            }
            std::thread::sleep(Duration::from_secs(10));
        }
    });
}

// ------------------------------------------------------------------ tray icon upkeep (v0.6.1)

/// Make a fresh tray icon (the old one, if any, is removed when it is dropped)
/// and push the current state into it.
fn rebuild_tray(why: &'static str, log_it: bool) {
    let tray = match Tray::new() {
        Ok(t) => t,
        Err(e) => {
            if log_it {
                log(&format!("could not create the tray icon again ({why}): {e}"));
            }
            return;
        }
    };
    wire_tray(&tray);
    with_app(|app| {
        app.tray = tray;
        app.icon_kind = None;
        app.menu_key.clear();
        app.refresh();
    });
    if log_it {
        log(&format!("tray icon added again ({why})"));
    }
}

/// From the taskbar watch: Windows' taskbar was (re)created, or PIA Lite was
/// started again while running (e.g. from the Start menu because no icon showed).
fn on_taskbar_event(why: &'static str) {
    if why.starts_with("PIA Lite was started again") && winutil::tray_icon_alive() {
        // the icon is there: open the panel, which is what starting it again asks for
        let mut open = false;
        with_app(|app| open = app.popup.is_some());
        if !open {
            toggle_popup();
        }
        return;
    }
    rebuild_tray(why, true);
}

thread_local! {
    static ICON_CHECK: slint::Timer = slint::Timer::default();
}

/// Every 5 s: if adding the icon failed (Slint gives up silently after one
/// try), add it again once the taskbar is there.
fn start_icon_check() {
    let misses = std::cell::Cell::new(0u32);
    ICON_CHECK.with(|t| {
        t.start(slint::TimerMode::Repeated, Duration::from_secs(5), move || {
            if winutil::tray_icon_alive() {
                misses.set(0);
                return;
            }
            let n = misses.get() + 1;
            misses.set(n);
            if !winutil::taskbar_ready() {
                if n == 1 || n.is_multiple_of(60) {
                    log("no tray icon yet - waiting for the taskbar / desktop tray");
                }
                return;
            }
            // the first tries right away, then once a minute (logged every 5 min)
            if n <= 3 || n.is_multiple_of(12) {
                rebuild_tray("the tray icon was missing", n <= 3 || n.is_multiple_of(60));
            }
        });
    });
}

/// At sign-in the tray can start before Windows' taskbar exists; wait for it
/// (up to 30 s - the checks above take over after that).
fn wait_for_taskbar() {
    let t0 = Instant::now();
    while !winutil::taskbar_ready() && t0.elapsed() < Duration::from_secs(30) {
        std::thread::sleep(Duration::from_millis(100));
    }
    let waited = t0.elapsed();
    if waited >= Duration::from_millis(100) {
        log(&format!(
            "waited {:.1} s for the taskbar / desktop tray{}",
            waited.as_secs_f32(),
            if winutil::taskbar_ready() { "" } else { " - still not there, adding the icon when it appears" }
        ));
    }
}

pub fn run() -> Result<(), String> {
    // started by a sign-in entry this user turned off for themselves
    if std::env::args().any(|a| a == "--autostart") && winutil::autostart_opted_out() {
        return Ok(());
    }
    if !winutil::single_instance() {
        // already running - maybe without a visible icon: ask it to show itself
        if winutil::ask_running_copy_to_show() {
            log("already running - asked the running copy to show itself");
        }
        return Ok(());
    }
    winutil::migrate_old_install();
    if !piactl::exe().exists() {
        log(&format!("piactl not found at {}", piactl::exe().display()));
    }
    select_backend()?;
    // before the icon is added, so a "TaskbarCreated" right after can't be missed
    winutil::watch_taskbar(on_taskbar_event);
    wait_for_taskbar();

    let tray = Tray::new().map_err(|e| format!("could not create tray icon: {e}"))?;
    wire_tray(&tray);
    let st = State {
        autostart: winutil::autostart_enabled(),
        connect_on_start: pia_connect_on_launch(),
        install: guard::install_record(),
        ..Default::default()
    };
    let first_run = st.install.is_none() && !cfg!(windows) && guard::guard_exe().is_file() && !winutil::guard_service_registered();
    APP.with(|cell| {
        *cell.borrow_mut() = Some(App {
            tray,
            popup: None,
            features: None,
            st,
            light_taskbar: winutil::light_taskbar(),
            icon_kind: None,
            menu_key: String::new(),
            list_key: String::new(),
            popup_closed_at: None,
        })
    });
    with_app(|app| app.refresh());
    start_workers();
    start_icon_check();
    start_update_checks();
    // PIA keeps the VPN up with its own window closed only in "background mode"
    std::thread::spawn(|| {
        if let Err(e) = piactl::run(&["background", "enable"]) {
            log(&format!("PIA background mode: {e}"));
        }
    });
    // Linux packages install files only: the first start asks what to set up (once)
    let marker = log_dir().join("features-offered");
    if first_run && !marker.exists() {
        let _ = std::fs::create_dir_all(log_dir());
        let _ = std::fs::write(&marker, b"1");
        slint::Timer::single_shot(Duration::from_secs(2), open_features);
    }

    let result = slint::run_event_loop_until_quit().map_err(|e| format!("event loop: {e}"));
    piactl::shutdown();
    APP.with(|cell| cell.borrow_mut().take());
    result
}

#[cfg(test)]
mod tests {
    /// Review V63-03: the note reaches the guard BEFORE PIA's command; if it
    /// can't, PIA's command still runs and the problem is reported.
    #[test]
    fn the_guard_hears_the_users_choice_first() {
        let steps = vec![vec![super::GUARD_STEP.to_string(), "user".into(), "disconnect".into()], vec!["disconnect".to_string()]];
        let order = std::cell::RefCell::new(vec![]);
        let (err, warn) = super::run_steps(
            &steps,
            &mut |a| {
                order.borrow_mut().push(format!("piactl {}", a.join(" ")));
                Ok(())
            },
            &mut |n| {
                order.borrow_mut().push(format!("guard {n}"));
                Ok(())
            },
        );
        assert_eq!(*order.borrow(), ["guard user disconnect", "piactl disconnect"]);
        assert!(err.is_none() && warn.is_none());
        // the guard doesn't answer (twice): Disconnect still goes to PIA, and it's reported
        order.borrow_mut().clear();
        let (err, warn) = super::run_steps(
            &steps,
            &mut |a| {
                order.borrow_mut().push(format!("piactl {}", a.join(" ")));
                Ok(())
            },
            &mut |n| {
                order.borrow_mut().push(format!("guard {n}"));
                Err("timed out".into())
            },
        );
        assert_eq!(*order.borrow(), ["guard user disconnect", "guard user disconnect", "piactl disconnect"], "one retry, then PIA anyway");
        assert!(err.is_none() && warn.is_some_and(|w| w.contains("timed out")));
        // V64-03: no guard installed - still tried first, a failure is silent
        order.borrow_mut().clear();
        let quiet = vec![vec![super::GUARD_STEP_QUIET.to_string(), "user".into(), "connect".into()], vec!["connect".to_string()]];
        let (err, warn) = super::run_steps(
            &quiet,
            &mut |a| {
                order.borrow_mut().push(format!("piactl {}", a.join(" ")));
                Ok(())
            },
            &mut |n| {
                order.borrow_mut().push(format!("guard {n}"));
                Err("no pipe".into())
            },
        );
        assert_eq!(order.borrow().last().map(String::as_str), Some("piactl connect"));
        assert!(order.borrow().first().is_some_and(|c| c == "guard user connect"), "tried first");
        assert!(err.is_none() && warn.is_none(), "no warning when no guard is installed");
        // ... and when the guard IS there (status not polled yet), the note gets through first
        order.borrow_mut().clear();
        let (_, warn) = super::run_steps(
            &quiet,
            &mut |a| {
                order.borrow_mut().push(format!("piactl {}", a.join(" ")));
                Ok(())
            },
            &mut |n| {
                order.borrow_mut().push(format!("guard {n}"));
                Ok(())
            },
        );
        assert_eq!(*order.borrow(), ["guard user connect", "piactl connect"]);
        assert!(warn.is_none());
        // a failing piactl step stops the rest
        let two = vec![vec!["set".to_string(), "region".into(), "x".into()], vec!["connect".to_string()]];
        let mut n = 0;
        let (err, _) = super::run_steps(
            &two,
            &mut |_| {
                n += 1;
                Err("bad".into())
            },
            &mut |_| Ok(()),
        );
        assert!(err.is_some() && n == 1);
    }

    #[test]
    fn features_window_builds_a_safe_setup_command() {
        use super::{setup_args, Choices};
        let all = Choices { guard: true, dns: true, hotel: true, autostart: true, provider: 1, mode: 2, ..Default::default() };
        let a = setup_args(&all, "1000").unwrap();
        assert_eq!(a.join(" "), "setup --features guard,dns,hotel,autostart --mode always --dns cloudflare --user 1000");
        let no_guard = Choices { dns: true, hotel: true, mode: 1, ..Default::default() };
        let a = setup_args(&no_guard, "S-1-5-21-1-2-3-1001").unwrap();
        assert_eq!(a.join(" "), "setup --features none --user S-1-5-21-1-2-3-1001", "DNS and hotel need the guard");
        let next = |id: &str| Choices { guard: true, dns: true, provider: 4, mode: 1, nextdns_id: id.into(), ..Default::default() };
        assert!(setup_args(&next(""), "").is_err(), "NextDNS needs a profile ID");
        assert!(setup_args(&next("ab c12"), "").is_err());
        let a = setup_args(&next(" abc123 "), "").unwrap();
        assert!(a.join(" ").ends_with("--dns nextdns --nextdns-id abc123"));
        assert!(a.iter().all(|w| crate::guard::safe_arg(w)), "every word passes the elevated-command check");
    }

    #[test]
    fn connect_on_launch_reads_the_exact_field() {
        assert!(super::parse_connect_on_launch(r#"{"connectOnLaunch": true, "x": 1}"#));
        assert!(!super::parse_connect_on_launch(r#"{"connectOnLaunch": false}"#));
        assert!(!super::parse_connect_on_launch(r#"{"note": "\"connectOnLaunch\":true"}"#), "text inside another field");
        assert!(!super::parse_connect_on_launch("not json"));
    }
}

#[cfg(test)]
mod screenshot {
    //! Dev helper: renders the panel offscreen with the same software renderer.
    //! PIALITE_SHOT=<dir> cargo test render_panel
    use slint::platform::software_renderer::{MinimalSoftwareWindow, PremultipliedRgbaColor, RepaintBufferType};
    use slint::platform::{Platform, WindowAdapter, WindowEvent};
    use slint::ComponentHandle;
    use std::rc::Rc;

    struct TestPlatform(Rc<MinimalSoftwareWindow>);
    impl Platform for TestPlatform {
        fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn render_panel() {
        let Ok(dir) = std::env::var("PIALITE_SHOT") else { return };
        let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
        slint::platform::set_platform(Box::new(TestPlatform(window.clone()))).unwrap();
        let w = 640usize;
        window.dispatch_event(WindowEvent::ScaleFactorChanged { scale_factor: 2.0 });
        window.set_size(slint::PhysicalSize::new(w as u32, 1000));
        let ids: Vec<String> =
            ["us-east", "us-new-york", "ca-toronto", "us-east-streaming-optimized", "netherlands"].iter().map(|s| s.to_string()).collect();
        for (name, kind, header, regions_page) in
            [("connected", 1, "CONNECTED", false), ("disconnected", 3, "DISCONNECTED", false), ("regions", 1, "CONNECTED", true)]
        {
            let p = crate::Popup::new().unwrap();
            p.set_kind(kind);
            p.set_header_text(header.into());
            p.set_region_label(crate::regions::pretty("us-east").into());
            p.set_vpn_ip(if kind == 1 { "151.x.x.x" } else { "-" }.into());
            p.set_hint_text(if kind == 1 { "Click to disconnect" } else { "Click to connect" }.into());
            let mut list = vec!["auto".to_string()];
            list.extend(crate::regions::filtered(&ids, ""));
            p.set_region_list(super::entries(&list, Some("us-east")));
            p.set_show_regions(regions_page);
            p.set_hotel_enabled(true);
            p.set_hotel_label("Hotel Wi-Fi login (VPN off for 3 min)".into());
            p.set_guard_text(
                if kind == 1 { "Quad9 encrypted: OK  |  Block: at startup" } else { "Internet blocked until the VPN connects" }.into(),
            );
            let h = if name == "connected" {
                p.set_update_text("Update available: 0.9.1 - click to install".into());
                1084
            } else {
                1000
            };
            window.set_size(slint::PhysicalSize::new(w as u32, h as u32));
            p.show().unwrap();
            let h = h as usize;
            let mut buf = vec![PremultipliedRgbaColor::default(); w * h];
            window.request_redraw();
            window.draw_if_needed(|r| {
                r.render(&mut buf, w);
            });
            let mut rgba = Vec::with_capacity(w * h * 4);
            for c in &buf {
                rgba.extend_from_slice(&[c.red, c.green, c.blue, c.alpha]);
            }
            std::fs::write(format!("{dir}/panel_{name}.rgba"), rgba).unwrap();
            p.hide().unwrap();
        }
        // the features window (first start on Linux, "Features..." in the menu)
        let (fw, fh) = (880usize, 1000usize);
        window.set_size(slint::PhysicalSize::new(fw as u32, fh as u32));
        let f = crate::Features::new().unwrap();
        f.set_provider(4);
        f.set_nextdns_id("abc123".into());
        f.set_apply_label("Apply (asks for your password)".into());
        f.set_status_text("First start: choose what you want, then Apply. You can change it later from the tray menu.".into());
        f.show().unwrap();
        let mut buf = vec![PremultipliedRgbaColor::default(); fw * fh];
        window.request_redraw();
        window.draw_if_needed(|r| {
            r.render(&mut buf, fw);
        });
        let rgba: Vec<u8> = buf.iter().flat_map(|c| [c.red, c.green, c.blue, c.alpha]).collect();
        std::fs::write(format!("{dir}/features.rgba"), rgba).unwrap();
        f.hide().unwrap();
    }
}
