//! Talking to the guard service.
//!
//! Windows: named pipe `\\.\pipe\PiaLiteGuard`. The service creates it with an
//! access list that only lets SYSTEM, Administrators and the user who installed
//! PIA Lite connect (audit P0-01), and refuses connections from other PCs. We
//! ask only for read/write of data (review N-04), never for GENERIC_WRITE.
//! The client refuses to talk to a pipe that isn't served from session 0 (only
//! Windows services run there), so an ordinary program can't pose as the guard
//! by grabbing the name first. Elsewhere (tests): TCP on 127.0.0.1.
//!
//! Protocol: one request line `<proto> <command>\n`, one reply line
//! `ok <text or JSON>` or `error <message>`.
//!
//! Every request has a deadline (review V3-06): the pipe is opened for
//! overlapped I/O and each read/write is cancelled when time is up, so a
//! stuck service can't hang the tray or the command line. A command that
//! timed out on our side may still finish in the service - read the status
//! again to see what happened.

pub const PROTO: u32 = 2;
pub const PIPE_NAME: &str = r"\\.\pipe\PiaLiteGuard";
pub const MAX_REQUEST: usize = 512;
pub const MAX_REPLY: usize = 64 * 1024;

pub fn format_request(cmd: &str) -> String {
    format!("{PROTO} {}\n", cmd.trim())
}

/// Server side: strip and check the protocol number.
pub fn parse_request(line: &str) -> Result<&str, String> {
    let line = line.trim();
    let (ver, cmd) = line.split_once(' ').unwrap_or((line, ""));
    match ver.parse::<u32>() {
        Ok(PROTO) if !cmd.trim().is_empty() => Ok(cmd.trim()),
        Ok(PROTO) => Err("empty command".into()),
        Ok(v) => Err(format!("unsupported protocol {v} (this guard speaks {PROTO}) - reinstall PIA Lite so both parts match")),
        Err(_) => Err("bad request".into()),
    }
}

/// Client side: "ok X" -> Ok(X), "error X" -> Err(X).
pub fn parse_reply(line: &str) -> Result<String, String> {
    let line = line.trim_end_matches(['\r', '\n']);
    if let Some(rest) = line.strip_prefix("ok") {
        Ok(rest.trim_start().to_string())
    } else if let Some(rest) = line.strip_prefix("error") {
        Err(rest.trim_start().to_string())
    } else {
        Err("garbled reply from guard service".into())
    }
}

/// Read one line (up to `cap` bytes) from a byte stream.
pub fn read_line(r: &mut impl std::io::Read, cap: usize) -> Result<String, String> {
    let mut buf = Vec::with_capacity(256);
    let mut b = [0u8; 1024];
    loop {
        let n = r.read(&mut b).map_err(|e| format!("guard service: {e}"))?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&b[..n]);
        if let Some(p) = buf.iter().position(|&c| c == b'\n') {
            buf.truncate(p);
            break;
        }
        if buf.len() > cap {
            return Err("reply too long".into());
        }
    }
    String::from_utf8(buf).map_err(|_| "reply not text".to_string())
}

/// Default time a command may take (the slowest, hotel login, needs PIA to
/// answer several times; the service itself waits at most 15 s for a turn).
pub const REQUEST_LIMIT: std::time::Duration = std::time::Duration::from_secs(60);

/// Send one command to the guard service and return its reply.
pub fn request(cmd: &str) -> Result<String, String> {
    request_within(cmd, REQUEST_LIMIT)
}

/// Same, with an explicit time limit for the whole exchange.
pub fn request_within(cmd: &str, limit: std::time::Duration) -> Result<String, String> {
    let line = transport::exchange(&format_request(cmd), limit)?;
    parse_reply(&line)
}

#[cfg(windows)]
mod transport {
    use super::*;
    use crate::winio;
    use std::fs::File;
    use std::os::windows::io::FromRawHandle;
    use std::ptr::{null, null_mut};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY, HANDLE, INVALID_HANDLE_VALUE,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA, OPEN_EXISTING, SECURITY_IDENTIFICATION,
        SECURITY_SQOS_PRESENT, SYNCHRONIZE,
    };
    use windows_sys::Win32::System::Pipes::{GetNamedPipeServerSessionId, WaitNamedPipeW};
    use windows_sys::Win32::System::Threading::CreateEventW;

    /// Open the guard's pipe (synchronous handle - used by the pipe self-test).
    pub fn open() -> Result<File, String> {
        open_raw(0, Instant::now() + Duration::from_secs(10)).map(|h| unsafe { File::from_raw_handle(h as _) })
    }

    /// Open the guard's pipe (checked to be served by a Windows service).
    fn open_raw(flags: u32, until: Instant) -> Result<HANDLE, String> {
        let name: Vec<u16> = PIPE_NAME.encode_utf16().chain(Some(0)).collect();
        for _ in 0..20 {
            // SECURITY_IDENTIFICATION: the server may learn who we are, but can't act as us.
            let h = unsafe {
                CreateFileW(
                    name.as_ptr(),
                    // exactly what the service grants approved accounts (no FILE_APPEND_DATA)
                    FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                    0,
                    null(),
                    OPEN_EXISTING,
                    SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION | flags,
                    null_mut(),
                )
            };
            if h != INVALID_HANDLE_VALUE {
                let mut session = u32::MAX;
                let ok = unsafe { GetNamedPipeServerSessionId(h, &mut session) } != 0;
                if !ok || (session != 0 && std::env::var_os("PIALITE_DEV_PIPE").is_none()) {
                    unsafe { CloseHandle(h) };
                    return Err("refusing to talk to the guard pipe: it is not served by a Windows service".into());
                }
                return Ok(h);
            }
            match unsafe { GetLastError() } {
                ERROR_PIPE_BUSY if Instant::now() < until => {
                    unsafe { WaitNamedPipeW(name.as_ptr(), 500) };
                }
                ERROR_PIPE_BUSY => break,
                ERROR_FILE_NOT_FOUND => return Err("guard service not running".into()),
                ERROR_ACCESS_DENIED => return Err("this Windows account is not allowed to control the guard service".into()),
                e => return Err(format!("could not reach the guard service (error {e})")),
            }
        }
        Err("guard service busy".into())
    }

    /// Closes the pipe handle and its event.
    struct Handles(HANDLE, HANDLE);
    impl Drop for Handles {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
                if !self.1.is_null() {
                    CloseHandle(self.1);
                }
            }
        }
    }

    pub fn exchange(req: &str, limit: Duration) -> Result<String, String> {
        let until = Instant::now() + limit;
        let h = open_raw(FILE_FLAG_OVERLAPPED, until)?;
        let ev = unsafe { CreateEventW(null(), 1, 0, null()) };
        let hs = Handles(h, ev);
        if ev.is_null() {
            return Err("could not talk to the guard service (no event)".into());
        }
        // SAFETY: both handles are open (closed by `hs` when this returns) and
        // the pipe was opened with FILE_FLAG_OVERLAPPED.
        let pio = unsafe { winio::PipeIo::new(hs.0, hs.1) };
        if !pio.write_all(req.as_bytes(), until) {
            return Err(format!("guard service did not take the request within {} s", limit.as_secs()));
        }
        match pio.read_line(MAX_REPLY, until) {
            Ok(b) => String::from_utf8(b).map_err(|_| "reply not text".to_string()),
            Err("timed out") => Err(format!("guard service did not answer within {} s", limit.as_secs())),
            Err(e) => Err(format!("guard service: reply {e}")),
        }
    }
}

/// Linux: a Unix socket (/run/pialite/guard.sock); the guard learns who is
/// asking from the kernel (SO_PEERCRED). Tests use TCP on localhost instead
/// (PIALITE_IPC_PORT set).
#[cfg(not(windows))]
mod transport {
    use super::*;
    use std::io::Write;
    use std::net::TcpStream;
    use std::time::Duration;

    pub fn port() -> u16 {
        std::env::var("PIALITE_IPC_PORT").ok().and_then(|p| p.parse().ok()).unwrap_or(53530)
    }

    pub fn socket_path() -> std::path::PathBuf {
        std::env::var_os("PIALITE_IPC_SOCKET").map(Into::into).unwrap_or_else(|| "/run/pialite/guard.sock".into())
    }

    /// Tests (and only tests) talk TCP.
    pub fn use_tcp() -> bool {
        std::env::var_os("PIALITE_IPC_PORT").is_some()
    }

    pub fn exchange(req: &str, limit: Duration) -> Result<String, String> {
        if use_tcp() {
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port()));
            let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).map_err(|_| "guard service not running".to_string())?;
            let _ = s.set_read_timeout(Some(limit));
            s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
            return read_line(&mut s, MAX_REPLY);
        }
        let path = socket_path();
        let mut s = std::os::unix::net::UnixStream::connect(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => "guard service not running".to_string(),
            std::io::ErrorKind::PermissionDenied => format!("not allowed to use {}", path.display()),
            _ => format!("guard service: {e}"),
        })?;
        let _ = s.set_read_timeout(Some(limit));
        let _ = s.set_write_timeout(Some(Duration::from_secs(5)));
        s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        read_line(&mut s, MAX_REPLY)
    }
}

/// A raw connection to the guard pipe (used by the pipe self-test).
#[cfg(windows)]
pub use transport::open as open_pipe;
#[cfg(not(windows))]
pub use transport::{port as test_port, socket_path, use_tcp};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn framing() {
        assert_eq!(format_request(" status "), "2 status\n");
        assert_eq!(parse_request("2 mode always\r\n"), Ok("mode always"));
        assert!(parse_request("1 status").unwrap_err().contains("unsupported protocol 1"));
        assert!(parse_request("status").is_err());
        assert!(parse_request("2").is_err());
        assert_eq!(parse_reply("ok {\"a\":1}\n"), Ok("{\"a\":1}".into()));
        assert_eq!(parse_reply("ok"), Ok("".into()));
        assert_eq!(parse_reply("error nope"), Err("nope".into()));
        assert!(parse_reply("HTTP/1.1 400").is_err());
        let mut r = std::io::Cursor::new(b"ok hi\nextra".to_vec());
        assert_eq!(read_line(&mut r, 100).unwrap(), "ok hi");
        let mut r = std::io::Cursor::new(vec![b'x'; 5000]);
        assert!(read_line(&mut r, 100).is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn a_silent_service_cannot_hang_the_client() {
        // review V3-06: the service takes the request but never answers
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        std::env::set_var("PIALITE_IPC_PORT", l.local_addr().unwrap().port().to_string());
        std::thread::spawn(move || {
            let mut keep = vec![];
            for c in l.incoming().flatten() {
                keep.push(c);
            }
        });
        let t = std::time::Instant::now();
        assert!(request_within("status", std::time::Duration::from_millis(300)).is_err());
        assert!(t.elapsed() < std::time::Duration::from_secs(2), "{:?}", t.elapsed());
    }
}
