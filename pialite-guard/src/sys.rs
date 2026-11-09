//! System integration per operating system: the guard service, the data
//! folder's permissions, PIA's DNS setting, start-at-sign-in tasks and the
//! install record the updater reads. Used by `setup` / `teardown`.
//!
//! Windows: service "PiaLiteGuard" (LocalSystem) via sc.exe, permissions via
//! icacls, tasks via schtasks. Linux: systemd units pialite-guard.service and
//! pialite-boot.service (shipped by the packages; written by `setup` when
//! missing, e.g. the portable .tar.gz).

use crate::config;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

#[cfg(windows)]
pub const SERVICE: &str = "PiaLiteGuard";
#[cfg(not(windows))]
pub const SERVICE: &str = "pialite-guard.service";

/// Run a program; (success, stdout+stderr).
pub fn run(prog: &str, args: &[&str]) -> Result<(bool, String), String> {
    let mut c = Command::new(prog);
    c.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let out = c.output().map_err(|e| format!("{prog}: {e}"))?;
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    Ok((out.status.success(), text))
}

#[cfg_attr(not(windows), allow(dead_code))]
fn must(prog: &str, args: &[&str]) -> Result<String, String> {
    let (ok, out) = run(prog, args)?;
    if ok {
        Ok(out)
    } else {
        Err(format!("{prog} {}: {}", args.join(" "), out.lines().find(|l| !l.trim().is_empty()).unwrap_or("failed").trim()))
    }
}

// ------------------------------------------------------------------ admin

/// Running with full rights (elevated administrator / root)?
#[cfg(windows)]
pub fn is_admin() -> bool {
    // "net session" only works elevated - no extra API bindings needed
    run("net", &["session"]).map(|(ok, _)| ok).unwrap_or(false)
}

#[cfg(not(windows))]
pub fn is_admin() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Linux: the user who asked for this (sudo / pkexec), so the tray of that
/// user may talk to the guard.
#[cfg(not(windows))]
pub fn invoking_uid() -> Option<u32> {
    ["PKEXEC_UID", "SUDO_UID"].iter().find_map(|v| std::env::var(v).ok()?.parse().ok()).filter(|u| *u != 0)
}

// ---------------------------------------------------------------- service

#[cfg(windows)]
fn sc(args: &[&str]) -> Result<(bool, String), String> {
    run("sc.exe", args)
}

#[cfg(windows)]
pub fn service_installed() -> bool {
    sc(&["query", SERVICE]).map(|(ok, _)| ok).unwrap_or(false)
}

#[cfg(windows)]
pub fn service_running() -> bool {
    sc(&["query", SERVICE]).map(|(ok, out)| ok && out.contains("RUNNING")).unwrap_or(false)
}

#[cfg(windows)]
pub fn stop_service() -> Result<(), String> {
    if !service_installed() {
        return Ok(());
    }
    let _ = sc(&["stop", SERVICE]);
    let until = Instant::now() + Duration::from_secs(30);
    while Instant::now() < until {
        if sc(&["query", SERVICE]).map(|(_, o)| o.contains("STOPPED")).unwrap_or(false) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("the guard service did not stop within 30 s - restart the PC and try again".into())
}

#[cfg(windows)]
pub fn start_service() -> Result<(), String> {
    let (_, out) = sc(&["start", SERVICE])?;
    if out.contains("FAILED") && !out.contains("1056") {
        // 1056 = already running
        return Err(out.trim().to_string());
    }
    Ok(())
}

/// Create the service, or point an existing one (an older install) at `exe`.
#[cfg(windows)]
pub fn register_service(exe: &Path) -> Result<(), String> {
    let bin = format!("\"{}\" service", exe.display());
    if service_installed() {
        must("sc.exe", &["config", SERVICE, "binPath=", &bin, "start=", "auto", "obj=", "LocalSystem"])?;
    } else {
        must("sc.exe", &["create", SERVICE, "binPath=", &bin, "start=", "auto", "obj=", "LocalSystem", "DisplayName=", "PIA Lite Guard"])?;
    }
    let _ = sc(&["description", SERVICE, "PIA Lite: kill switch while the VPN is not connected, encrypted DNS, hotel login."]);
    // restart after a crash: 5 s, 5 s, then 30 s
    let _ = sc(&["failure", SERVICE, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/30000"]);
    Ok(())
}

#[cfg(windows)]
pub fn remove_service() -> Result<(), String> {
    if !service_installed() {
        return Ok(());
    }
    stop_service()?;
    must("sc.exe", &["delete", SERVICE]).map(|_| ())
}

#[cfg(not(windows))]
fn systemctl(args: &[&str]) -> Result<(bool, String), String> {
    let p = ["/usr/bin/systemctl", "/bin/systemctl"]
        .into_iter()
        .find(|p| Path::new(p).is_file())
        .ok_or("systemd (systemctl) not found - PIA Lite's guard needs systemd")?;
    run(p, args)
}

/// Set up by `setup` (enabled), not just shipped by a package: packages
/// install the unit file, but the guard runs only if the user chose it.
#[cfg(not(windows))]
pub fn service_installed() -> bool {
    let wants = Path::new("/etc/systemd/system/multi-user.target.wants").join(SERVICE);
    std::fs::symlink_metadata(wants).is_ok() || Path::new("/etc/systemd/system").join(SERVICE).is_file()
}

/// The unit file exists somewhere (packaged or written by setup).
#[cfg(not(windows))]
fn unit_present() -> bool {
    unit_dirs().iter().any(|d| d.join(SERVICE).is_file())
}

#[cfg(not(windows))]
pub fn service_running() -> bool {
    systemctl(&["is-active", "--quiet", SERVICE]).map(|(ok, _)| ok).unwrap_or(false)
}

#[cfg(not(windows))]
pub fn stop_service() -> Result<(), String> {
    if !unit_present() {
        return Ok(());
    }
    systemctl(&["stop", SERVICE]).map(|_| ())
}

#[cfg(not(windows))]
pub fn start_service() -> Result<(), String> {
    let (ok, out) = systemctl(&["restart", SERVICE])?;
    if ok {
        Ok(())
    } else {
        Err(format!("systemctl restart {SERVICE}: {}", out.trim()))
    }
}

#[cfg(not(windows))]
fn unit_dirs() -> Vec<PathBuf> {
    ["/etc/systemd/system", "/usr/lib/systemd/system", "/lib/systemd/system"].iter().map(PathBuf::from).collect()
}

/// The guard's unit (the packages ship the same text).
#[cfg(not(windows))]
pub fn guard_unit(exe: &Path) -> String {
    format!(
        "[Unit]\n\
         Description=PIA Lite guard (kill switch, encrypted DNS, hotel login)\n\
         Documentation=https://github.com/NicholasBly/PIALite\n\
         After=pialite-boot.service network.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         ExecStart={exe} run\n\
         # the temporary allow-all goes with the service - also after a crash\n\
         ExecStopPost={exe} firewall-close\n\
         Restart=on-failure\n\
         RestartSec=3\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        exe = exe.display()
    )
}

/// Loads the saved rules before the network starts (the Linux counterpart of
/// Windows' boot-time filters).
#[cfg(not(windows))]
pub fn boot_unit() -> String {
    "[Unit]\n\
     Description=PIA Lite: block rules before the network starts\n\
     Documentation=https://github.com/NicholasBly/PIALite\n\
     DefaultDependencies=no\n\
     After=local-fs.target\n\
     Before=network-pre.target shutdown.target\n\
     Wants=network-pre.target\n\
     Conflicts=shutdown.target\n\
     ConditionPathExists=/var/lib/pialite/firewall.nft\n\
     \n\
     [Service]\n\
     Type=oneshot\n\
     RemainAfterExit=yes\n\
     ExecStart=/bin/sh -c 'exec nft -f /var/lib/pialite/firewall.nft'\n\
     \n\
     [Install]\n\
     WantedBy=sysinit.target\n"
        .to_string()
}

#[cfg(not(windows))]
pub fn register_service(exe: &Path) -> Result<(), String> {
    // packages ship the units in /usr/lib/systemd/system; otherwise write them
    if !unit_dirs()[1..].iter().any(|d| d.join(SERVICE).is_file()) {
        std::fs::write(Path::new("/etc/systemd/system").join(SERVICE), guard_unit(exe))
            .map_err(|e| format!("writing the service unit: {e}"))?;
        std::fs::write("/etc/systemd/system/pialite-boot.service", boot_unit()).map_err(|e| format!("writing the boot unit: {e}"))?;
    }
    must_ok(systemctl(&["daemon-reload"])?, "systemctl daemon-reload")?;
    must_ok(systemctl(&["enable", SERVICE])?, "systemctl enable")
}

#[cfg(not(windows))]
fn must_ok((ok, out): (bool, String), what: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(format!("{what}: {}", out.trim()))
    }
}

#[cfg(not(windows))]
pub fn remove_service() -> Result<(), String> {
    if !unit_present() {
        return Ok(());
    }
    let _ = systemctl(&["disable", "--now", SERVICE]);
    let _ = systemctl(&["disable", "pialite-boot.service"]);
    // only the units we wrote ourselves (packages remove their own)
    for f in [SERVICE, "pialite-boot.service"] {
        let p = Path::new("/etc/systemd/system").join(f);
        if p.is_file() {
            std::fs::remove_file(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        }
    }
    let _ = systemctl(&["daemon-reload"]);
    Ok(())
}

/// Wait until the guard answers on its control channel.
pub fn wait_for_guard(limit: Duration) -> Result<pialite_common::status::GuardStatus, String> {
    let until = Instant::now() + limit;
    loop {
        match pialite_common::ipc::request_within("status", Duration::from_secs(5)) {
            Ok(j) => return serde_json::from_str(&j).map_err(|e| format!("unreadable status: {e}")),
            Err(e) if Instant::now() >= until => return Err(format!("the guard service didn't answer within {} s ({e})", limit.as_secs())),
            Err(_) => std::thread::sleep(Duration::from_millis(300)),
        }
    }
}

// ------------------------------------------------------------ data folder

/// Create the data folder and allow only the system and administrators to
/// change it (Windows: SYSTEM + Administrators full, Users read; Linux:
/// root-owned, 0755, the settings file 0600).
pub fn protect_data_dir() -> Result<PathBuf, String> {
    let dir = config::data_dir();
    if let Ok(m) = std::fs::symlink_metadata(&dir) {
        if m.file_type().is_symlink() {
            return Err(format!("{} is a link - PIA Lite never follows those; remove it and run setup again", dir.display()));
        }
    }
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    #[cfg(windows)]
    {
        let d = dir.display().to_string();
        must("icacls", &[&d, "/setowner", "*S-1-5-32-544", "/T", "/C", "/Q"])?;
        must(
            "icacls",
            &[&d, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX", "/Q"],
        )?;
        // children: inherit only (drops anything else a user may have added)
        must("icacls", &[&format!("{d}\\*"), "/reset", "/T", "/C", "/Q"]).or_else(|e| {
            if std::fs::read_dir(&dir).map(|mut r| r.next().is_none()).unwrap_or(false) {
                Ok(String::new())
            } else {
                Err(e)
            }
        })?;
    }
    #[cfg(not(windows))]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let m = std::fs::metadata(&dir).map_err(|e| e.to_string())?;
        if m.uid() != 0 {
            unsafe {
                let c = std::ffi::CString::new(dir.as_os_str().as_encoded_bytes()).map_err(|e| e.to_string())?;
                if libc::chown(c.as_ptr(), 0, 0) != 0 {
                    return Err(format!("{}: could not give it to root", dir.display()));
                }
            }
        }
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).map_err(|e| e.to_string())?;
        let cfg = dir.join("guard.json");
        if cfg.is_file() {
            std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
        }
    }
    Ok(dir)
}

// ---------------------------------------------------------- install record

/// What this installation is - read by the tray's updater to download the
/// right kind of update and keep the same features.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
#[serde(default)]
pub struct InstallRecord {
    /// "msi", "portable", "deb", "rpm", "tarball" or "source".
    pub kind: String,
    pub version: String,
    /// "guard", "dns", "hotel", "autostart", "fastpia"
    pub features: Vec<String>,
    /// Where the programs are.
    pub dir: String,
    /// MSI: this version's product code (the tray's "Change features" opens it).
    pub product_code: String,
    /// Windows: PIA's "Start PIA First" task was disabled by setup (put back on removal).
    pub pia_task_disabled: bool,
}

pub fn record_path() -> PathBuf {
    config::data_dir().join("install.json")
}

pub fn write_record(r: &InstallRecord) -> Result<(), String> {
    let text = serde_json::to_string_pretty(r).map_err(|e| e.to_string())?;
    let p = record_path();
    let tmp = p.with_extension("tmp");
    std::fs::write(&tmp, text).and_then(|_| std::fs::rename(&tmp, &p)).map_err(|e| format!("{}: {e}", p.display()))
}

pub fn read_record() -> Option<InstallRecord> {
    serde_json::from_str(&std::fs::read_to_string(record_path()).ok()?).ok()
}

// ------------------------------------------------------- start at sign-in

/// Windows: the tray at sign-in (any user) as a scheduled task - it starts
/// within a second or two, sooner than the Run key.
#[cfg(windows)]
pub fn set_tray_autostart(on: bool, tray_exe: &Path) -> Result<(), String> {
    let name = "PIA Lite Tray";
    if !on {
        let _ = run("schtasks", &["/Delete", "/TN", name, "/F"]);
        return Ok(());
    }
    let xml = task_xml(
        "Starts the PIA Lite tray when you sign in.",
        &tray_exe.display().to_string(),
        "--autostart",
        "<GroupId>S-1-5-32-545</GroupId><RunLevel>LeastPrivilege</RunLevel>",
    );
    create_task(name, &xml)
}

#[cfg(windows)]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

#[cfg(windows)]
fn task_xml(description: &str, command: &str, args: &str, principal: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>{}</Description><Author>PIA Lite</Author></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author">{principal}</Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>5</Priority>
    <StartWhenAvailable>false</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Author"><Exec><Command>"{}"</Command><Arguments>{}</Arguments></Exec></Actions>
</Task>"#,
        xml_escape(description),
        xml_escape(command),
        xml_escape(args)
    )
}

#[cfg(windows)]
fn create_task(name: &str, xml: &str) -> Result<(), String> {
    // schtasks wants the XML as a file (UTF-16 with BOM)
    let path = std::env::temp_dir().join(format!("pialite-task-{}.xml", std::process::id()));
    let mut bytes = vec![0xFF, 0xFE];
    for u in xml.encode_utf16() {
        bytes.extend_from_slice(&u.to_le_bytes());
    }
    std::fs::write(&path, bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    let r = must("schtasks", &["/Create", "/TN", name, "/XML", &path.display().to_string(), "/F"]);
    let _ = std::fs::remove_file(&path);
    r.map(|_| ())
}

/// Linux: /etc/xdg/autostart/pialite-tray.desktop (written by setup, so a
/// feature turned off is really off). Each user can still turn it off for
/// themselves in the tray (an override in ~/.config/autostart).
#[cfg(not(windows))]
pub fn set_tray_autostart(on: bool, tray_exe: &Path) -> Result<(), String> {
    let p = Path::new(AUTOSTART_FILE);
    if !on {
        return match std::fs::remove_file(p) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("{}: {e}", p.display())),
            _ => Ok(()),
        };
    }
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
    }
    std::fs::write(p, autostart_entry(tray_exe)).map_err(|e| format!("{}: {e}", p.display()))
}

#[cfg(not(windows))]
pub const AUTOSTART_FILE: &str = "/etc/xdg/autostart/pialite-tray.desktop";

#[cfg(not(windows))]
pub fn autostart_entry(tray_exe: &Path) -> String {
    format!(
        "[Desktop Entry]\nType=Application\nName=PIA Lite\nComment=Lightweight tray for Private Internet Access\n\
         Exec=\"{}\" --autostart\nIcon=pialite\nTerminal=false\nCategories=Network;\nX-GNOME-Autostart-enabled=true\n",
        tray_exe.display()
    )
}

/// The folder this program runs from.
pub fn exe_dir() -> PathBuf {
    std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)).unwrap_or_else(|| PathBuf::from("."))
}
