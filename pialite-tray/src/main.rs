// PIA Lite tray - a lightweight replacement for PIA's window.
// PIA's background service, drivers, kill switch and split tunnel stay untouched;
// this app only talks to them through PIA's official piactl tool.
#![cfg_attr(windows, windows_subsystem = "windows")]

mod app;
mod guard;
mod icons;
mod piactl;
mod regions;
mod winutil;

slint::include_modules!();

fn main() {
    if let Err(e) = app::run() {
        app::log(&format!("fatal: {e}"));
    }
}
