//! PIA's official command-line tool (piactl), run with a time limit so a stuck
//! PIA service can never hang the tray or the guard (audit P2-13).

use std::io::{BufRead, BufReader, Read};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

/// Time limits per kind of command.
pub const T_GET: Duration = Duration::from_secs(5);
pub const T_SET: Duration = Duration::from_secs(10);
pub const T_CONNECT: Duration = Duration::from_secs(20);
pub const T_REGIONS: Duration = Duration::from_secs(15);

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
static CHILDREN: Mutex<Vec<Child>> = Mutex::new(Vec::new());

/// Where PIA is installed (PIA's own source: Windows "Private Internet
/// Access" under Program Files; Linux /opt/piavpn).
pub fn pia_dir() -> PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("ProgramFiles")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\Program Files"))
            .join("Private Internet Access")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("/opt/piavpn")
    }
}

pub fn exe() -> PathBuf {
    std::env::var_os("PIALITE_PIACTL").map(PathBuf::from).unwrap_or_else(|| {
        if cfg!(windows) {
            pia_dir().join("piactl.exe")
        } else {
            pia_dir().join("bin").join("piactl")
        }
    })
}

/// PIA's daemon settings file (read-only for us). PIALITE_PIA_SETTINGS
/// points somewhere else (tests with a fake piactl).
pub fn settings_path() -> PathBuf {
    std::env::var_os("PIALITE_PIA_SETTINGS")
        .map(PathBuf::from)
        .unwrap_or_else(|| pia_dir().join(if cfg!(windows) { "data" } else { "etc" }).join("settings.json"))
}

/// Every piactl we start is put in a Windows "job" that is closed when this
/// program ends - even if it is force-killed - and Windows then ends the
/// piactl helpers too. (Without this, killing the tray left its three
/// `piactl monitor` helpers running.)
#[cfg(windows)]
fn tie_to_us(child: &Child) {
    use std::os::windows::io::AsRawHandle;
    use std::sync::OnceLock;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation, SetInformationJobObject,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };
    static JOB: OnceLock<usize> = OnceLock::new();
    let job = *JOB.get_or_init(|| unsafe {
        let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        if h.is_null() {
            return 0;
        }
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(
            h,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        );
        h as usize // the handle stays open for the life of the process on purpose
    });
    if job != 0 {
        unsafe { AssignProcessToJobObject(job as _, child.as_raw_handle() as _) };
    }
}
#[cfg(not(windows))]
fn tie_to_us(_child: &Child) {}

fn command() -> Command {
    let mut c = Command::new(exe());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    c.stdin(Stdio::null());
    c
}

/// Run piactl and return its trimmed output. Killed if it takes longer than `timeout`.
pub fn run(args: &[&str], timeout: Duration) -> Result<String, String> {
    let what = format!("piactl {}", args.first().copied().unwrap_or(""));
    let mut child =
        command().args(args).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().map_err(|e| format!("could not start piactl: {e}"))?;
    tie_to_us(&child);
    // read both pipes on helper threads so a chatty child can't block on a full pipe
    let out = child.stdout.take().map(|o| thread::spawn(move || read_capped(o, 1 << 20)));
    let err = child.stderr.take().map(|e| thread::spawn(move || read_capped(e, 64 << 10)));
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{what} timed out after {}s (PIA service not responding?)", timeout.as_secs()));
            }
            Ok(None) => thread::sleep(Duration::from_millis(25)),
            Err(e) => return Err(format!("{what}: {e}")),
        }
    };
    let stdout = out.and_then(|t| t.join().ok()).unwrap_or_default();
    let stderr = err.and_then(|t| t.join().ok()).unwrap_or_default();
    let text = String::from_utf8_lossy(&stdout).trim().to_string();
    if status.success() {
        Ok(text)
    } else {
        Err(format!("{what} failed ({status}): {text} {}", String::from_utf8_lossy(&stderr).trim()).trim().to_string())
    }
}

fn read_capped(r: impl Read, cap: u64) -> Vec<u8> {
    let mut v = Vec::new();
    let _ = r.take(cap).read_to_end(&mut v);
    v
}

pub fn is_shutdown() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

/// Keep `piactl monitor <kind>` running and report each value. `None` is
/// reported when piactl exits (PIA's service unreachable); restarts every 3 s.
pub fn monitor(kind: &'static str, on_value: impl Fn(Option<String>) + Send + 'static) {
    thread::spawn(move || {
        while !is_shutdown() {
            if let Ok(mut child) = command().args(["monitor", kind]).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() {
                tie_to_us(&child);
                let stdout = child.stdout.take();
                if let Ok(mut list) = CHILDREN.lock() {
                    list.push(child);
                }
                if let Some(out) = stdout {
                    for line in BufReader::new(out).lines() {
                        let Ok(line) = line else { break };
                        let v = line.trim();
                        if !v.is_empty() {
                            on_value(Some(v.to_string()));
                        }
                    }
                }
                if let Ok(mut list) = CHILDREN.lock() {
                    list.retain_mut(|c| matches!(c.try_wait(), Ok(None)));
                }
            }
            if is_shutdown() {
                break;
            }
            on_value(None);
            thread::sleep(Duration::from_secs(3));
        }
    });
}

/// Stop all monitor processes.
pub fn shutdown() {
    SHUTDOWN.store(true, Ordering::SeqCst);
    if let Ok(mut list) = CHILDREN.lock() {
        for c in list.iter_mut() {
            let _ = c.kill();
            let _ = c.wait();
        }
        list.clear();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    // Uses a shell script standing in for piactl. Tests share the env var, so
    // they run in one test function.
    #[test]
    fn timeouts_and_errors() {
        let dir = std::env::temp_dir().join(format!("pialite-piactl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("piactl");
        std::fs::write(
            &fake,
            "#!/bin/sh\ncase \"$1\" in\n  get) echo Connected;;\n  hang) sleep 30;;\n  fail) echo nope >&2; exit 3;;\nesac\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::env::set_var("PIALITE_PIACTL", &fake);

        assert_eq!(run(&["get", "connectionstate"], T_GET).unwrap(), "Connected");
        let t = Instant::now();
        let e = run(&["hang"], Duration::from_millis(300)).unwrap_err();
        assert!(e.contains("timed out"), "{e}");
        assert!(t.elapsed() < Duration::from_secs(5), "killed promptly");
        let e = run(&["fail"], T_GET).unwrap_err();
        assert!(e.contains("nope"), "{e}");
        let _ = std::fs::remove_dir_all(dir);
    }
}
