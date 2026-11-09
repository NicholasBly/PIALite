//! Control channel server (audit P0-01, P2-12, review N-04, N-05).
//!
//! Windows: named pipe `\\.\pipe\PiaLiteGuard` whose access list allows only
//! SYSTEM, Administrators and the Windows account(s) the installer recorded
//! (`allowed_sids` in guard.json; if none were recorded, nobody else).
//! Approved accounts get read + write of data only - NOT the right to create
//! another instance of the pipe (FILE_GENERIC_WRITE would include it, N-04).
//! Created with FILE_FLAG_FIRST_PIPE_INSTANCE so nobody else can hold the name,
//! rejects remote clients, at most 4 clients at a time.
//!
//! Every client gets a hard time budget for the pipe itself (N-05): 5 s to
//! send its request, 2 s for us to hand over the reply, then up to 3 s for it
//! to read the reply and hang up - after that it is cut off. All pipe I/O is
//! overlapped with a timeout and cancelled when the time is up (shared code in
//! pialite_common::winio; no blocking FlushFileBuffers). Running the command
//! is bounded too (V3-06): a command waits at most 15 s for the one before it,
//! then answers "busy"; the slowest one (hotel login) is bounded by piactl's
//! own time limits. Worst case per client: about 75 s.
//!
//! The access list is built ONCE when the service starts: a change of the
//! approved accounts takes effect after a service restart (V3-11).
//!
//! Commands that weaken protection need an elevated administrator (the tray
//! asks Windows for "Run as administrator" for those) - see Guard::handle.
//!
//! Known limit (documented): a program running as *you* can use the pipe just
//! like the tray can - for the commands that don't need an administrator.
//!
//! Elsewhere (tests): plain TCP on 127.0.0.1.

use crate::guard::Guard;
use pialite_common::ipc::{parse_request, MAX_REQUEST};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

const MAX_ACTIVE: usize = 4;

fn reply_for(g: &Arc<Guard>, line: &str, admin: bool) -> String {
    match parse_request(line) {
        Ok(cmd) => match g.handle(cmd, admin) {
            Ok(text) => format!("ok {text}\n"),
            Err(e) => format!("error {}\n", e.replace('\n', " ")),
        },
        Err(e) => format!("error {e}\n"),
    }
}

/// What an approved (non-admin) account may do with the pipe: read data,
/// write data, read attributes, wait on it. 0x100083 =
/// SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_WRITE_DATA | FILE_READ_DATA.
/// Leaves out FILE_APPEND_DATA (= FILE_CREATE_PIPE_INSTANCE).
pub const CLIENT_RIGHTS: u32 = 0x0010_0083;

/// SDDL access list for the pipe.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn pipe_sddl(allowed_sids: &[String]) -> String {
    // P = protected (no inherited entries); GA = full (SYSTEM, elevated admins)
    let mut sddl = String::from("D:P(A;;GA;;;SY)(A;;GA;;;BA)");
    for sid in allowed_sids {
        sddl.push_str(&format!("(A;;0x{CLIENT_RIGHTS:x};;;{sid})"));
    }
    sddl
}

pub fn serve(guard: Arc<Guard>) {
    std::thread::spawn(move || server::run(guard));
}

#[cfg(windows)]
mod server {
    use super::*;
    use crate::config::log;
    use pialite_common::winio::{Op, PipeIo};
    use std::ptr::{null, null_mut};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, LocalFree, ERROR_IO_PENDING, ERROR_PIPE_CONNECTED, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows_sys::Win32::Security::{
        CheckTokenMembership, CreateWellKnownSid, RevertToSelf, WinBuiltinAdministratorsSid, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
        SECURITY_MAX_SID_SIZE, TOKEN_QUERY,
    };
    use windows_sys::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX};
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, ImpersonateNamedPipeClient, PIPE_READMODE_BYTE,
        PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
    };
    use windows_sys::Win32::System::Threading::{CreateEventW, GetCurrentThread, OpenThreadToken, WaitForSingleObject, INFINITE};
    use windows_sys::Win32::System::IO::{GetOverlappedResult, OVERLAPPED};

    const READ_LIMIT: Duration = Duration::from_secs(5);
    const WRITE_LIMIT: Duration = Duration::from_secs(2);
    const LINGER_LIMIT: Duration = Duration::from_secs(3);

    /// One pipe instance + the event its overlapped I/O signals.
    struct Pipe {
        h: HANDLE,
        ev: HANDLE,
    }
    unsafe impl Send for Pipe {}
    impl Drop for Pipe {
        fn drop(&mut self) {
            // No FlushFileBuffers: it waits for the client without a time limit (N-05).
            // Whatever the client hasn't read by now is dropped.
            unsafe {
                DisconnectNamedPipe(self.h);
                CloseHandle(self.h);
                CloseHandle(self.ev);
            }
        }
    }

    impl Pipe {
        fn pio(&self) -> PipeIo {
            // SAFETY: both handles live as long as this Pipe; created overlapped
            unsafe { PipeIo::new(self.h, self.ev) }
        }

        fn io(&self, op: Op, limit: Duration) -> Option<u32> {
            self.pio().io(op, limit)
        }

        /// Wait for a client (no time limit: this is the listener).
        fn accept(&self) -> bool {
            let mut ov = OVERLAPPED { hEvent: self.ev, ..Default::default() };
            if unsafe { ConnectNamedPipe(self.h, &mut ov) } != 0 {
                return true;
            }
            match unsafe { GetLastError() } {
                ERROR_PIPE_CONNECTED => true,
                ERROR_IO_PENDING => {
                    let mut n = 0u32;
                    unsafe { WaitForSingleObject(self.ev, INFINITE) };
                    unsafe { GetOverlappedResult(self.h, &ov, &mut n, 0) != 0 }
                }
                _ => false,
            }
        }

        /// Read one request line within READ_LIMIT in total.
        fn read_request(&self) -> Option<String> {
            let deadline = Instant::now() + READ_LIMIT;
            let mut buf = Vec::new();
            loop {
                let left = deadline.checked_duration_since(Instant::now())?;
                let mut tmp = [0u8; 512];
                let n = self.io(Op::Read(&mut tmp), left)? as usize;
                if n == 0 {
                    return None;
                }
                buf.extend_from_slice(&tmp[..n]);
                if let Some(i) = buf.iter().position(|&c| c == b'\n') {
                    buf.truncate(i);
                    return String::from_utf8(buf).ok();
                }
                if buf.len() > MAX_REQUEST {
                    return None;
                }
            }
        }

        /// Hand over the reply within `limit` in total.
        fn write_all(&self, data: &[u8], limit: Duration) -> bool {
            self.pio().write_all(data, Instant::now() + limit)
        }

        /// Give the client up to `limit` to read the reply and hang up (a read
        /// on our side ends when it closes its end). Then it's cut off.
        fn linger(&self, limit: Duration) {
            let mut b = [0u8; 16];
            let _ = self.io(Op::Read(&mut b), limit);
        }
    }

    struct Sd(PSECURITY_DESCRIPTOR);
    impl Drop for Sd {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0 as _) };
        }
    }

    fn security(allowed: &[String]) -> Result<Sd, String> {
        let sddl: Vec<u16> = pipe_sddl(allowed).encode_utf16().chain(Some(0)).collect();
        let mut sd: PSECURITY_DESCRIPTOR = null_mut();
        if unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.as_ptr(), SDDL_REVISION_1, &mut sd, null_mut()) } == 0 {
            return Err(format!("bad pipe access list (error {})", unsafe { GetLastError() }));
        }
        Ok(Sd(sd))
    }

    fn create(sd: &Sd, first: bool) -> Result<Pipe, u32> {
        let name: Vec<u16> = pialite_common::ipc::PIPE_NAME.encode_utf16().chain(Some(0)).collect();
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        let ev = unsafe { CreateEventW(null(), 1, 0, null()) };
        if ev.is_null() {
            return Err(unsafe { GetLastError() });
        }
        let open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED | if first { FILE_FLAG_FIRST_PIPE_INSTANCE } else { 0 };
        let h = unsafe {
            CreateNamedPipeW(
                name.as_ptr(),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                (MAX_ACTIVE + 2) as u32,
                64 * 1024,
                4096,
                0,
                &sa,
            )
        };
        if h == INVALID_HANDLE_VALUE {
            let e = unsafe { GetLastError() };
            unsafe { CloseHandle(ev) };
            Err(e)
        } else {
            Ok(Pipe { h, ev })
        }
    }

    /// Is the program on the other end an *elevated* administrator? (A normal
    /// admin account without "Run as administrator" has the Administrators group
    /// disabled, so this is false for it.) Clients connect with identification-
    /// level impersonation: enough to look at their identity, nothing more.
    fn caller_is_admin(p: &Pipe) -> bool {
        unsafe {
            if ImpersonateNamedPipeClient(p.h) == 0 {
                return false;
            }
            let mut tok: HANDLE = null_mut();
            let opened = OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut tok) != 0;
            RevertToSelf();
            if !opened {
                return false;
            }
            let mut sid = [0u8; SECURITY_MAX_SID_SIZE as usize];
            let mut size = sid.len() as u32;
            let mut member = 0i32;
            let ok = CreateWellKnownSid(WinBuiltinAdministratorsSid, null_mut(), sid.as_mut_ptr() as _, &mut size) != 0
                && CheckTokenMembership(tok, sid.as_mut_ptr() as _, &mut member) != 0
                && member != 0;
            CloseHandle(tok);
            ok
        }
    }

    pub fn run(guard: Arc<Guard>) {
        let active = Arc::new(AtomicUsize::new(0));
        let mut first = true;
        let mut warned = false;
        let mut busy_warned = false;
        // the access list is fixed for the life of the service (V3-11)
        let allowed = guard.allowed_sids();
        let sd = loop {
            match security(&allowed) {
                Ok(sd) => break sd,
                Err(e) => {
                    log(&e);
                    std::thread::sleep(Duration::from_secs(5));
                }
            }
        };
        loop {
            let pipe = match create(&sd, first) {
                Ok(p) => p,
                Err(code) => {
                    if !warned {
                        // ERROR_ACCESS_DENIED here means another program already owns the name
                        log(&format!("cannot create control pipe (error {code}) - another program may be holding its name; retrying"));
                        warned = true;
                    }
                    std::thread::sleep(Duration::from_secs(5));
                    continue;
                }
            };
            if first {
                log("control pipe ready");
                if allowed.is_empty() {
                    log(
                        "no Windows account approved for the control pipe - only elevated administrators can use it (re-run the installer)",
                    );
                }
            }
            first = false;
            warned = false;
            if !pipe.accept() {
                continue;
            }
            if active.load(Ordering::SeqCst) >= MAX_ACTIVE {
                if !busy_warned {
                    log("control pipe: all 4 slots busy - turning clients away (slow or stuck clients are cut off after 10 s)");
                    busy_warned = true;
                }
                // short, bounded: the listener must never get stuck on one client
                if pipe.write_all(b"error busy\n", Duration::from_millis(200)) {
                    pipe.linger(Duration::from_millis(200));
                }
                continue; // dropped -> disconnected
            }
            busy_warned = false;
            active.fetch_add(1, Ordering::SeqCst);
            let (g, active2) = (guard.clone(), active.clone());
            std::thread::spawn(move || {
                if let Some(line) = pipe.read_request() {
                    let admin = caller_is_admin(&pipe);
                    if pipe.write_all(reply_for(&g, &line, admin).as_bytes(), WRITE_LIMIT) {
                        pipe.linger(LINGER_LIMIT);
                    }
                }
                drop(pipe);
                active2.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }
}

#[cfg(not(windows))]
mod server {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::time::Duration;

    pub fn run(guard: Arc<Guard>) {
        if !pialite_common::ipc::use_tcp() {
            return unix::run(guard);
        }
        let port = pialite_common::ipc::test_port();
        let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) else { return };
        let active = Arc::new(AtomicUsize::new(0));
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            if active.load(Ordering::SeqCst) >= MAX_ACTIVE {
                let _ = s.write_all(b"error busy\n");
                continue;
            }
            active.fetch_add(1, Ordering::SeqCst);
            let (g, active2) = (guard.clone(), active.clone());
            std::thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
                if let Ok(line) = pialite_common::ipc::read_line(&mut (&s).take(MAX_REQUEST as u64), MAX_REQUEST) {
                    let _ = s.write_all(reply_for(&g, &line, true).as_bytes());
                }
                active2.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }
}

/// Linux: members of this group (and user ids given with `set-users`) may
/// use the guard without root - the tray of the user who installed it.
#[cfg(not(windows))]
pub const USERS_GROUP: &str = "pialite";

/// Linux: a user's name, from /etc/passwd.
#[cfg(not(windows))]
pub fn user_name(uid: u32) -> Option<String> {
    passwd_entry(&std::fs::read_to_string("/etc/passwd").ok()?, uid).map(|(n, _)| n)
}

/// (name, primary group id) of a user id in passwd-format text.
#[cfg(not(windows))]
fn passwd_entry(text: &str, uid: u32) -> Option<(String, u32)> {
    text.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 4 && f[2].parse() == Ok(uid)).then(|| Some((f[0].to_string(), f[3].parse().ok()?))).flatten()
    })
}

/// Is the user a member of `group` (listed, or as primary group)? Read
/// fresh each time, so adding someone takes effect without signing out.
#[cfg(not(windows))]
pub fn user_in_group(uid: u32, group: &str) -> bool {
    let (Ok(p), Ok(g)) = (std::fs::read_to_string("/etc/passwd"), std::fs::read_to_string("/etc/group")) else { return false };
    member_of(&p, &g, uid, group)
}

#[cfg(not(windows))]
fn member_of(passwd: &str, groups: &str, uid: u32, group: &str) -> bool {
    let Some((name, primary)) = passwd_entry(passwd, uid) else { return false };
    groups.lines().any(|l| {
        let f: Vec<&str> = l.split(':').collect();
        f.len() >= 4 && f[0] == group && (f[2].parse() == Ok(primary) || f[3].split(',').any(|m| m.trim() == name))
    })
}

/// Linux: /run/pialite/guard.sock. Anyone may connect (mode 0666), but the
/// kernel tells the guard who it is: root = admin; members of group
/// "pialite" and users listed with `set-users` (user ids) may use it without
/// admin rights; others are refused - the same rule as the Windows pipe
/// (review N-04).
#[cfg(not(windows))]
mod unix {
    use super::*;
    use crate::config::log;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::io::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::time::Duration;

    /// The connecting process's user id, from the kernel.
    fn peer_uid(s: &UnixStream) -> Option<u32> {
        let mut cred = libc::ucred { pid: 0, uid: 0, gid: 0 };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(s.as_raw_fd(), libc::SOL_SOCKET, libc::SO_PEERCRED, &mut cred as *mut _ as *mut libc::c_void, &mut len)
        };
        (rc == 0).then_some(cred.uid)
    }

    pub fn run(guard: Arc<Guard>) {
        let path = pialite_common::ipc::socket_path();
        if let Some(d) = path.parent() {
            let _ = std::fs::create_dir_all(d);
            let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o755));
        }
        let _ = std::fs::remove_file(&path); // a stale socket from a previous run
        let listener = match UnixListener::bind(&path) {
            Ok(l) => l,
            Err(e) => {
                log(&format!("control socket {}: {e}", path.display()));
                return;
            }
        };
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666));
        log("control socket ready");
        let active = Arc::new(AtomicUsize::new(0));
        for s in listener.incoming() {
            let Ok(mut s) = s else { continue };
            let Some(uid) = peer_uid(&s) else { continue };
            let admin = uid == 0;
            if !admin && !guard.cfg().allowed_uids.contains(&uid) && !super::user_in_group(uid, super::USERS_GROUP) {
                let who = super::user_name(uid).unwrap_or_else(|| uid.to_string());
                let _ = s.write_all(
                    format!(
                        "error not allowed: user '{who}' isn't approved (an admin can run: sudo usermod -aG {} {who})\n",
                        super::USERS_GROUP
                    )
                    .as_bytes(),
                );
                continue;
            }
            if active.load(Ordering::SeqCst) >= MAX_ACTIVE {
                let _ = s.write_all(b"error busy\n");
                continue;
            }
            active.fetch_add(1, Ordering::SeqCst);
            let (g, active2) = (guard.clone(), active.clone());
            std::thread::spawn(move || {
                let _ = s.set_read_timeout(Some(Duration::from_secs(10)));
                let _ = s.set_write_timeout(Some(Duration::from_secs(10)));
                if let Ok(line) = pialite_common::ipc::read_line(&mut (&s).take(MAX_REQUEST as u64), MAX_REQUEST) {
                    let _ = s.write_all(reply_for(&g, &line, admin).as_bytes());
                }
                active2.fetch_sub(1, Ordering::SeqCst);
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn linux_group_membership() {
        let passwd = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000:Alice:/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/sh\ncarol:x:1002:990::/home/carol:/bin/sh\n";
        let groups = "root:x:0:\nalice:x:1000:\npialite:x:990:alice\nsudo:x:27:bob\n";
        assert!(member_of(passwd, groups, 1000, "pialite"), "listed member");
        assert!(member_of(passwd, groups, 1002, "pialite"), "primary group");
        assert!(!member_of(passwd, groups, 1001, "pialite"));
        assert!(!member_of(passwd, groups, 4242, "pialite"), "unknown user");
        assert!(!member_of(passwd, "pialite:x:990:alicex\n", 1000, "pialite"), "names match exactly");
        assert_eq!(passwd_entry(passwd, 1001), Some(("bob".into(), 1001)));
    }

    #[test]
    fn sddl() {
        // no approved account -> nobody but SYSTEM and elevated admins (review N-04)
        assert_eq!(pipe_sddl(&[]), "D:P(A;;GA;;;SY)(A;;GA;;;BA)");
        let one = pipe_sddl(&["S-1-5-21-1-2-3-1001".into()]);
        assert_eq!(one, "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x100083;;;S-1-5-21-1-2-3-1001)");
        assert!(!one.contains("GW") && !one.contains("IU"), "no generic write, no 'interactive users'");
        // read data | write data | read attributes | synchronize, and NOT append data (= create pipe instance, 0x4)
        assert_eq!(CLIENT_RIGHTS & 0x4, 0);
        assert_eq!(CLIENT_RIGHTS, 0x1 | 0x2 | 0x80 | 0x10_0000);
    }
}
