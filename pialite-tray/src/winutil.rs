//! Small Windows helpers. Each has a do-nothing version for other systems so the
//! rest of the code can be compile-checked anywhere.

#[cfg(windows)]
mod imp {
    use std::path::PathBuf;
    use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE};
    use winreg::RegKey;

    const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
    const RUN_VALUE: &str = "PiaLiteTray";

    /// True if this is the only copy running. If Windows can't even create the
    /// marker (very unusual) we say so in the log and try once more; a second
    /// tray icon is harmless, so after that we start anyway (audit P3-30).
    pub fn single_instance() -> bool {
        use windows_sys::Win32::Foundation::{GetLastError, ERROR_ALREADY_EXISTS};
        use windows_sys::Win32::System::Threading::CreateMutexW;
        let name: Vec<u16> = "Local\\PiaLiteTray\0".encode_utf16().collect();
        for attempt in 0..2 {
            // The handle is kept open for the life of the process on purpose.
            let h = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
            let err = unsafe { GetLastError() };
            if !h.is_null() {
                return err != ERROR_ALREADY_EXISTS;
            }
            crate::app::log(&format!("single-instance check failed (error {err}), attempt {}", attempt + 1));
            std::thread::sleep(std::time::Duration::from_millis(500));
        }
        true
    }

    /// Work area (desktop minus taskbar) of the monitor the mouse is on - that's
    /// where the tray icon was just clicked. Physical pixels: (left, top, right, bottom).
    pub fn work_area() -> (i32, i32, i32, i32) {
        use windows_sys::Win32::Foundation::{POINT, RECT};
        use windows_sys::Win32::Graphics::Gdi::{GetMonitorInfoW, MonitorFromPoint, MONITORINFO, MONITOR_DEFAULTTOPRIMARY};
        use windows_sys::Win32::UI::WindowsAndMessaging::{GetCursorPos, SystemParametersInfoW, SPI_GETWORKAREA};
        unsafe {
            let mut pt = POINT { x: 0, y: 0 };
            if GetCursorPos(&mut pt) != 0 {
                let mon = MonitorFromPoint(pt, MONITOR_DEFAULTTOPRIMARY);
                let mut mi: MONITORINFO = std::mem::zeroed();
                mi.cbSize = std::mem::size_of::<MONITORINFO>() as u32;
                if !mon.is_null() && GetMonitorInfoW(mon, &mut mi) != 0 {
                    let r = mi.rcWork;
                    return (r.left, r.top, r.right, r.bottom);
                }
            }
            let mut r = RECT { left: 0, top: 0, right: 1920, bottom: 1080 };
            SystemParametersInfoW(SPI_GETWORKAREA, 0, &mut r as *mut RECT as *mut core::ffi::c_void, 0);
            (r.left, r.top, r.right, r.bottom)
        }
    }

    /// Display scale (1.0 = 100%, 1.25 = 125% ...).
    pub fn system_scale() -> f32 {
        let dpi = unsafe { windows_sys::Win32::UI::HiDpi::GetDpiForSystem() };
        if dpi == 0 {
            1.0
        } else {
            dpi as f32 / 96.0
        }
    }

    /// True if the taskbar uses the light theme (then the icon glyph is drawn dark).
    pub fn light_taskbar() -> bool {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize", KEY_READ)
            .and_then(|k| k.get_value::<u32, _>("SystemUsesLightTheme"))
            .map(|v| v == 1)
            .unwrap_or(false)
    }

    fn exe_command() -> Option<String> {
        std::env::current_exe().ok().map(|p| format!("\"{}\"", p.display()))
    }

    const PREFS_KEY: &str = r"Software\PIA Lite";
    const MACHINE_TASK: &str = "PIA Lite Tray";

    /// The installer's sign-in task for every user (MSI "Start at sign-in").
    fn machine_task() -> bool {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("schtasks")
            .args(["/Query", "/TN", MACHINE_TASK])
            .creation_flags(0x0800_0000)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// This user turned the installer's sign-in start off for themselves.
    pub fn autostart_opted_out() -> bool {
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(PREFS_KEY, KEY_READ)
            .and_then(|k| k.get_value::<u32, _>("NoAutostart"))
            .map(|v| v == 1)
            .unwrap_or(false)
    }

    fn run_key_set() -> bool {
        let Some(want) = exe_command() else { return false };
        RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(RUN_KEY, KEY_READ)
            .and_then(|k| k.get_value::<String, _>(RUN_VALUE))
            .map(|v| v.eq_ignore_ascii_case(&want))
            .unwrap_or(false)
    }

    pub fn autostart_enabled() -> bool {
        (machine_task() && !autostart_opted_out()) || run_key_set()
    }

    /// With the installer's task: a per-user opt-out (no admin needed).
    /// Without it: the per-user "Run" list.
    pub fn set_autostart(on: bool) -> Result<(), String> {
        if machine_task() {
            let (k, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(PREFS_KEY).map_err(|e| format!("settings key: {e}"))?;
            k.set_value("NoAutostart", &u32::from(!on)).map_err(|e| format!("settings key: {e}"))?;
            if on {
                return Ok(());
            }
        }
        let key = RegKey::predef(HKEY_CURRENT_USER)
            .open_subkey_with_flags(RUN_KEY, KEY_READ | KEY_WRITE)
            .map_err(|e| format!("open Run key: {e}"))?;
        if on {
            let cmd = exe_command().ok_or("cannot find own exe path")?;
            key.set_value(RUN_VALUE, &cmd).map_err(|e| format!("set autostart: {e}"))
        } else {
            match key.delete_value(RUN_VALUE) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(format!("remove autostart: {e}")),
            }
        }
    }

    /// Open PIA's original app (for settings the tray doesn't cover, like split tunnel).
    pub fn open_pia() {
        let exe: PathBuf = pialite_common::piactl::pia_dir().join("pia-client.exe");
        if let Err(e) = std::process::Command::new(&exe).spawn() {
            crate::app::log(&format!("could not open {}: {e}", exe.display()));
        }
    }

    /// Open a web page in the default browser.
    pub fn open_url(url: &str) {
        if let Err(e) = std::process::Command::new("explorer.exe").arg(url).spawn() {
            crate::app::log(&format!("could not open {url}: {e}"));
        }
    }

    /// Run the guard's command line "as administrator" - Windows shows its
    /// prompt - and wait for it (review N-04: weakening the block needs an
    /// elevated administrator, so ordinary programs can't do it silently).
    pub fn run_elevated(args: &[&str]) -> Result<(), String> {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_CANCELLED, WAIT_OBJECT_0};
        use windows_sys::Win32::System::Com::{CoInitializeEx, COINIT_APARTMENTTHREADED, COINIT_DISABLE_OLE1DDE};
        use windows_sys::Win32::System::Threading::{GetExitCodeProcess, WaitForSingleObject};
        use windows_sys::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
        use windows_sys::Win32::UI::WindowsAndMessaging::SW_HIDE;
        let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(Some(0)).collect() };
        // ShellExecuteEx may hand off to shell extensions: COM on this (worker) thread
        unsafe { CoInitializeEx(std::ptr::null(), (COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE) as u32) };
        let exe = crate::guard::guard_exe();
        if !exe.is_file() {
            return Err(format!("{} not found - re-run the installer", exe.display()));
        }
        // only fixed words go on this command line (mode names, "hotel start")
        if args.iter().any(|a| !crate::guard::safe_arg(a)) {
            return Err("bad guard command".into());
        }
        let (verb, file, params) = (wide("runas"), wide(&exe.to_string_lossy()), wide(&args.join(" ")));
        let mut info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
        info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
        info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC;
        info.lpVerb = verb.as_ptr();
        info.lpFile = file.as_ptr();
        info.lpParameters = params.as_ptr();
        info.nShow = SW_HIDE;
        if unsafe { ShellExecuteExW(&mut info) } == 0 {
            let e = unsafe { GetLastError() };
            return Err(if e == ERROR_CANCELLED {
                "cancelled at the Windows prompt - nothing changed".into()
            } else {
                format!("could not run as administrator (error {e})")
            });
        }
        if info.hProcess.is_null() {
            return Err("could not run as administrator".into());
        }
        let mut code = 1u32;
        let done = unsafe { WaitForSingleObject(info.hProcess, 120_000) } == WAIT_OBJECT_0;
        unsafe {
            GetExitCodeProcess(info.hProcess, &mut code);
            CloseHandle(info.hProcess);
        }
        match (done, code) {
            (false, _) => Err("the guard command took too long".into()),
            (true, 0) => Ok(()),
            (true, c) => Err(format!("the guard refused (exit {c}) - see C:\\ProgramData\\PiaLite\\guard.log")),
        }
    }

    /// Before 0.9 the tray was copied to %LOCALAPPDATA%\PiaLite and started
    /// from the "Run" list. Running from the installer's folder now, that
    /// entry would start the old copy too: removed, and the old copy deleted
    /// (if it's still running, deleting is tried again at the next start).
    pub fn migrate_old_install() {
        let Some(base) = std::env::var_os("LOCALAPPDATA") else { return };
        let old = PathBuf::from(base).join("PiaLite").join("pialite-tray.exe");
        let Ok(me) = std::env::current_exe() else { return };
        let norm = |p: &std::path::Path| p.display().to_string().to_lowercase();
        if !old.is_file() || norm(&old) == norm(&me) {
            return;
        }
        if let Ok(k) = RegKey::predef(HKEY_CURRENT_USER).open_subkey_with_flags(RUN_KEY, KEY_READ | KEY_WRITE) {
            if k.get_value::<String, _>(RUN_VALUE).is_ok_and(|v| v.to_lowercase().contains(&norm(&old)))
                && k.delete_value(RUN_VALUE).is_ok()
            {
                crate::app::log("removed the old tray's startup entry (pre-0.9 install)");
            }
        }
        if std::fs::remove_file(&old).is_ok() {
            crate::app::log(&format!("deleted the old tray copy {}", old.display()));
        }
    }

    /// Is the guard service registered with Windows, whether or not it runs
    /// (review V65-04: not just "is the program file there")?
    pub fn guard_service_registered() -> bool {
        use windows_sys::Win32::System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS,
        };
        unsafe {
            let scm = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
            if scm.is_null() {
                return false;
            }
            let svc = OpenServiceW(scm, wide("PiaLiteGuard").as_ptr(), SERVICE_QUERY_STATUS);
            let found = !svc.is_null();
            if found {
                CloseServiceHandle(svc);
            }
            CloseServiceHandle(scm);
            found
        }
    }

    /// This user's Windows account ID (S-1-5-21-...), for setup's --user.
    pub fn my_user_id() -> String {
        use windows_sys::Win32::Foundation::{CloseHandle, LocalFree};
        use windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows_sys::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
        use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
        unsafe {
            let mut tok = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok) == 0 {
                return String::new();
            }
            let mut buf = vec![0u8; 256];
            let mut len = 0u32;
            let ok = GetTokenInformation(tok, TokenUser, buf.as_mut_ptr().cast(), buf.len() as u32, &mut len) != 0;
            CloseHandle(tok);
            if !ok {
                return String::new();
            }
            let user = &*(buf.as_ptr() as *const TOKEN_USER);
            let mut text: *mut u16 = std::ptr::null_mut();
            if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 || text.is_null() {
                return String::new();
            }
            let mut n = 0;
            while *text.add(n) != 0 {
                n += 1;
            }
            let s = String::from_utf16_lossy(std::slice::from_raw_parts(text, n));
            LocalFree(text.cast());
            s
        }
    }

    /// Start this program again (the MSI updater does this on Windows).
    pub fn restart_self() {
        if let Ok(exe) = std::env::current_exe() {
            let _ = std::process::Command::new(exe).spawn();
        }
        let _ = slint::quit_event_loop();
    }

    // ------------------------------------------------------------ tray icon upkeep
    //
    // Slint adds the tray icon once, from a message-only window. If Windows'
    // taskbar isn't there yet (the tray now starts within a second of sign-in,
    // v0.6.0) that one try fails silently - and a message-only window never
    // hears Windows' "TaskbarCreated" broadcast, so the icon never comes back.
    // These helpers let the app notice and add it again (v0.6.1).

    const WATCH_CLASS: &str = "PiaLiteTrayWatch";
    /// A second copy asks the running one to put its icon back.
    const WM_SHOW_AGAIN: u32 = windows_sys::Win32::UI::WindowsAndMessaging::WM_APP + 1;

    static ON_TASKBAR: std::sync::OnceLock<fn(&'static str)> = std::sync::OnceLock::new();
    static TASKBAR_MSG: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Is Windows' taskbar (with its notification area) there?
    pub fn taskbar_ready() -> bool {
        use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowExW, FindWindowW};
        let bar = unsafe { FindWindowW(wide("Shell_TrayWnd").as_ptr(), std::ptr::null()) };
        !bar.is_null() && !unsafe { FindWindowExW(bar, std::ptr::null_mut(), wide("TrayNotifyWnd").as_ptr(), std::ptr::null()) }.is_null()
    }

    /// Does this program have a live tray icon window? (Slint destroys its
    /// window when adding the icon fails, so "none" = no icon.)
    pub fn tray_icon_alive() -> bool {
        use windows_sys::Win32::System::Threading::GetCurrentProcessId;
        use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowExW, GetWindowThreadProcessId, HWND_MESSAGE};
        let class = wide("SlintSystemTrayWindow");
        let me = unsafe { GetCurrentProcessId() };
        let mut after = std::ptr::null_mut();
        for _ in 0..64 {
            let h = unsafe { FindWindowExW(HWND_MESSAGE, after, class.as_ptr(), std::ptr::null()) };
            if h.is_null() {
                return false;
            }
            let mut pid = 0u32;
            unsafe { GetWindowThreadProcessId(h, &mut pid) };
            if pid == me {
                return true;
            }
            after = h;
        }
        false
    }

    unsafe extern "system" fn watch_proc(
        hwnd: windows_sys::Win32::Foundation::HWND,
        msg: u32,
        wp: windows_sys::Win32::Foundation::WPARAM,
        lp: windows_sys::Win32::Foundation::LPARAM,
    ) -> windows_sys::Win32::Foundation::LRESULT {
        let tb = TASKBAR_MSG.load(std::sync::atomic::Ordering::Relaxed);
        let why = if tb != 0 && msg == tb {
            Some("Windows' taskbar was (re)created")
        } else if msg == WM_SHOW_AGAIN {
            Some("PIA Lite was started again")
        } else {
            None
        };
        if let (Some(why), Some(f)) = (why, ON_TASKBAR.get()) {
            let f = *f;
            // not from inside the window procedure: queued for the event loop
            let _ = slint::invoke_from_event_loop(move || f(why));
            return 0;
        }
        unsafe { windows_sys::Win32::UI::WindowsAndMessaging::DefWindowProcW(hwnd, msg, wp, lp) }
    }

    /// A hidden (not message-only) window that hears "TaskbarCreated" and a
    /// second copy's "show again"; `f` runs on the event loop for each.
    pub fn watch_taskbar(f: fn(&'static str)) {
        use windows_sys::Win32::System::LibraryLoader::GetModuleHandleW;
        use windows_sys::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, RegisterClassW, RegisterWindowMessageW, WNDCLASSW, WS_EX_TOOLWINDOW, WS_POPUP,
        };
        let _ = ON_TASKBAR.set(f);
        let id = unsafe { RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()) };
        TASKBAR_MSG.store(id, std::sync::atomic::Ordering::Relaxed);
        let class = wide(WATCH_CLASS);
        let inst = unsafe { GetModuleHandleW(std::ptr::null()) };
        let wc =
            WNDCLASSW { lpfnWndProc: Some(watch_proc), hInstance: inst, lpszClassName: class.as_ptr(), ..unsafe { std::mem::zeroed() } };
        unsafe { RegisterClassW(&wc) };
        let h = unsafe {
            CreateWindowExW(
                WS_EX_TOOLWINDOW,
                class.as_ptr(),
                wide("PIA Lite tray watch").as_ptr(),
                WS_POPUP,
                0,
                0,
                0,
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                inst,
                std::ptr::null(),
            )
        };
        if h.is_null() {
            crate::app::log("could not create the taskbar watch window - the tray icon won't come back by itself if Explorer restarts");
        }
    }

    /// From a second copy: ask the running one to put its icon back.
    pub fn ask_running_copy_to_show() -> bool {
        use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowW, PostMessageW};
        let h = unsafe { FindWindowW(wide(WATCH_CLASS).as_ptr(), std::ptr::null()) };
        !h.is_null() && unsafe { PostMessageW(h, WM_SHOW_AGAIN, 0, 0) } != 0
    }
}

#[cfg(not(windows))]
mod imp {
    //! Linux (and other Unix desktops): XDG autostart, pkexec for admin
    //! commands, xdg-open, a lock file for "only one copy", and a socket
    //! through which a second copy asks the running one to show its panel.
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;

    fn runtime_dir() -> PathBuf {
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join(format!("pialite-{}", unsafe { libc::getuid() })))
    }

    fn config_home() -> PathBuf {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config"))
    }

    pub fn single_instance() -> bool {
        let dir = runtime_dir();
        let _ = std::fs::create_dir_all(&dir);
        let Ok(f) = std::fs::OpenOptions::new().write(true).create(true).truncate(false).mode(0o600).open(dir.join("pialite-tray.lock"))
        else {
            return true; // can't tell: a second icon is harmless
        };
        if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return false;
        }
        std::mem::forget(f); // held for the life of the process
        true
    }

    /// Linux desktops put the tray at the top or the bottom; without a
    /// cursor position the panel goes to the top-right corner, below a bar.
    pub fn work_area() -> (i32, i32, i32, i32) {
        (0, 0, 1920, 1080)
    }
    pub fn system_scale() -> f32 {
        1.0
    }
    pub fn light_taskbar() -> bool {
        false
    }

    const MACHINE_ENTRY: &str = "/etc/xdg/autostart/pialite-tray.desktop";

    fn user_entry() -> PathBuf {
        config_home().join("autostart").join("pialite-tray.desktop")
    }

    fn hidden(path: &std::path::Path) -> bool {
        std::fs::read_to_string(path).map(|t| t.lines().any(|l| l.trim() == "Hidden=true")).unwrap_or(false)
    }

    pub fn autostart_enabled() -> bool {
        let user = user_entry();
        if std::path::Path::new(MACHINE_ENTRY).is_file() {
            !hidden(&user)
        } else {
            user.is_file() && !hidden(&user)
        }
    }

    /// With the installer's machine-wide entry: a per-user "Hidden=true"
    /// override turns it off (the XDG way). Without it: a per-user entry.
    pub fn set_autostart(on: bool) -> Result<(), String> {
        let user = user_entry();
        let machine = std::path::Path::new(MACHINE_ENTRY).is_file();
        if !on && !machine {
            return match std::fs::remove_file(&user) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("{}: {e}", user.display())),
                _ => Ok(()),
            };
        }
        if on && machine {
            return match std::fs::remove_file(&user) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(format!("{}: {e}", user.display())),
                _ => Ok(()),
            };
        }
        if let Some(d) = user.parent() {
            std::fs::create_dir_all(d).map_err(|e| format!("{}: {e}", d.display()))?;
        }
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let text = format!(
            "[Desktop Entry]\nType=Application\nName=PIA Lite\nExec=\"{}\" --autostart\nIcon=pialite\nTerminal=false\n{}",
            exe.display(),
            if on { "" } else { "Hidden=true\n" }
        );
        std::fs::write(&user, text).map_err(|e| format!("{}: {e}", user.display()))
    }

    /// Started by an autostart entry the user turned off for themselves.
    pub fn autostart_opted_out() -> bool {
        hidden(&user_entry())
    }

    pub fn open_pia() {
        let exe = pialite_common::piactl::pia_dir().join("bin").join("pia-client");
        if let Err(e) = std::process::Command::new(&exe).spawn() {
            crate::app::log(&format!("could not open {}: {e}", exe.display()));
        }
    }

    pub fn open_url(url: &str) {
        if let Err(e) = std::process::Command::new("xdg-open").arg(url).spawn() {
            crate::app::log(&format!("could not open {url}: {e}"));
        }
    }

    /// The guard's command line as root - pkexec asks for the password -
    /// and wait for it (weakening the block needs an administrator).
    pub fn run_elevated(args: &[&str]) -> Result<(), String> {
        let exe = crate::guard::guard_exe();
        if !exe.is_file() {
            return Err(format!("{} not found - re-run the installer", exe.display()));
        }
        if args.iter().any(|a| !crate::guard::safe_arg(a)) {
            return Err("bad guard command".into());
        }
        let pkexec = ["/usr/bin/pkexec", "/bin/pkexec"]
            .into_iter()
            .find(|p| std::path::Path::new(p).is_file())
            .ok_or("pkexec (polkit) is not installed - run the command with sudo instead")?;
        let out = std::process::Command::new(pkexec).arg(&exe).args(args).output().map_err(|e| format!("pkexec: {e}"))?;
        match out.status.code() {
            Some(0) => Ok(()),
            Some(126) | Some(127) => Err("cancelled at the password prompt - nothing changed".into()),
            _ => {
                let err = String::from_utf8_lossy(&out.stderr);
                let line = err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").trim_start_matches("ERROR: ").to_string();
                Err(if line.is_empty() { format!("the guard refused ({})", out.status) } else { line })
            }
        }
    }

    // ------------------------------------------------------------ tray icon upkeep
    //
    // The tray icon is a StatusNotifierItem. If the desktop's tray (the
    // StatusNotifierWatcher) isn't there yet when PIA Lite starts at sign-in,
    // Slint's one try fails and never comes back - the same problem v0.6.1
    // solved on Windows. These let the app wait for the tray and add the icon
    // again; anything that can't be asked counts as "fine" (no rebuild loop).

    const WATCHER: &str = "org.kde.StatusNotifierWatcher";

    fn bus() -> Option<&'static zbus::blocking::Connection> {
        static C: std::sync::OnceLock<Option<zbus::blocking::Connection>> = std::sync::OnceLock::new();
        C.get_or_init(|| zbus::blocking::Connection::session().ok()).as_ref()
    }

    /// Is the desktop's tray (StatusNotifierWatcher) there?
    pub fn taskbar_ready() -> bool {
        let Some(c) = bus() else { return true };
        let (Ok(d), Ok(name)) = (zbus::blocking::fdo::DBusProxy::new(c), zbus::names::BusName::try_from(WATCHER)) else { return true };
        d.name_has_owner(name).unwrap_or(true)
    }

    /// Is an icon of THIS process registered with the tray? (Each entry's bus
    /// name is asked for its process id - works however the tray lists it.)
    pub fn tray_icon_alive() -> bool {
        let Some(c) = bus() else { return true };
        if !taskbar_ready() {
            return false;
        }
        let items = zbus::blocking::proxy::Builder::<zbus::blocking::Proxy>::new(c)
            .destination(WATCHER)
            .and_then(|b| b.path("/StatusNotifierWatcher"))
            .and_then(|b| b.interface(WATCHER))
            .map(|b| b.cache_properties(zbus::proxy::CacheProperties::No))
            .and_then(|b| b.build())
            .and_then(|p| p.get_property::<Vec<String>>("RegisteredStatusNotifierItems"));
        let (Ok(items), Ok(d)) = (items, zbus::blocking::fdo::DBusProxy::new(c)) else { return true };
        let me = std::process::id();
        items.iter().any(|item| {
            let name = item.split('/').next().unwrap_or("");
            zbus::names::BusName::try_from(name).ok().and_then(|n| d.get_connection_unix_process_id(n).ok()) == Some(me)
        })
    }

    fn show_socket() -> PathBuf {
        runtime_dir().join("pialite-tray.sock")
    }

    /// A second copy connects here to ask for the panel.
    pub fn watch_taskbar(f: fn(&'static str)) {
        let path = show_socket();
        let _ = std::fs::remove_file(&path);
        let Ok(l) = UnixListener::bind(&path) else { return };
        std::thread::spawn(move || {
            for c in l.incoming().flatten() {
                drop(c);
                let _ = slint::invoke_from_event_loop(move || f("PIA Lite was started again"));
            }
        });
    }

    pub fn ask_running_copy_to_show() -> bool {
        UnixStream::connect(show_socket()).and_then(|mut s| s.write_all(b"show")).is_ok()
    }

    pub fn migrate_old_install() {}

    /// Was the guard service set up (enabled - a package alone only ships
    /// the unit file), whether or not it runs right now?
    pub fn guard_service_registered() -> bool {
        let wants = std::path::Path::new("/etc/systemd/system/multi-user.target.wants/pialite-guard.service");
        std::fs::symlink_metadata(wants).is_ok() || std::path::Path::new("/etc/systemd/system/pialite-guard.service").is_file()
    }

    /// This user, as the guard knows users (Linux user id).
    pub fn my_user_id() -> String {
        unsafe { libc::getuid() }.to_string()
    }

    /// Start this program again (after an update replaced it).
    pub fn restart_self() {
        use std::os::unix::process::CommandExt;
        let exe = std::env::current_exe().ok().map(|p| PathBuf::from(p.to_string_lossy().trim_end_matches(" (deleted)").to_string()));
        if let Some(exe) = exe {
            let e = std::process::Command::new(exe).exec(); // only returns on failure
            crate::app::log(&format!("could not restart: {e}"));
        }
    }
}

pub use imp::*;
