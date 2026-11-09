//! Overlapped (asynchronous) pipe I/O with hard time limits, shared by the
//! guard's pipe server and the pipe client (review N-05, V3-06). Every read or
//! write either finishes in time or is cancelled (CancelIoEx) and waited for,
//! so neither side can be held forever by the other.

use std::ptr::null_mut;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{GetLastError, ERROR_IO_PENDING, HANDLE, WAIT_OBJECT_0};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::Threading::WaitForSingleObject;
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

pub enum Op<'a> {
    Read(&'a mut [u8]),
    Write(&'a [u8]),
}

/// A pipe handle opened with FILE_FLAG_OVERLAPPED plus the manual-reset event
/// its I/O signals. Doesn't own them: whoever created them closes them.
#[derive(Clone, Copy)]
pub struct PipeIo {
    h: HANDLE,
    ev: HANDLE,
}

impl PipeIo {
    /// # Safety
    /// `h` must be an open pipe handle created with FILE_FLAG_OVERLAPPED and
    /// `ev` an open manual-reset event, both alive for as long as this is used.
    pub unsafe fn new(h: HANDLE, ev: HANDLE) -> PipeIo {
        PipeIo { h, ev }
    }

    /// One overlapped read or write, cancelled if it doesn't finish in
    /// `limit`. Returns the bytes moved, or None (failed, closed, too slow).
    pub fn io(&self, op: Op, limit: Duration) -> Option<u32> {
        let (h, ev) = (self.h, self.ev);
        let mut ov = OVERLAPPED { hEvent: ev, ..Default::default() };
        let started = unsafe {
            match op {
                Op::Read(b) => ReadFile(h, b.as_mut_ptr(), b.len() as u32, null_mut(), &mut ov),
                Op::Write(b) => WriteFile(h, b.as_ptr(), b.len() as u32, null_mut(), &mut ov),
            }
        };
        if started == 0 && unsafe { GetLastError() } != ERROR_IO_PENDING {
            return None; // e.g. ERROR_BROKEN_PIPE: the other side hung up
        }
        let ms = limit.as_millis().min(u32::MAX as u128 - 1) as u32;
        let mut n = 0u32;
        if unsafe { WaitForSingleObject(ev, ms) } != WAIT_OBJECT_0 {
            unsafe {
                CancelIoEx(h, &ov);
                GetOverlappedResult(h, &ov, &mut n, 1); // wait for the cancel before `ov` goes away
            }
            return None;
        }
        (unsafe { GetOverlappedResult(h, &ov, &mut n, 0) } != 0).then_some(n)
    }

    /// Write everything before `until`.
    pub fn write_all(&self, data: &[u8], until: Instant) -> bool {
        let mut off = 0;
        while off < data.len() {
            let Some(l) = left(until) else { return false };
            match self.io(Op::Write(&data[off..]), l) {
                Some(n) if n > 0 => off += n as usize,
                _ => return false,
            }
        }
        true
    }

    /// Read one line (without the newline, at most `cap` bytes) before `until`.
    pub fn read_line(&self, cap: usize, until: Instant) -> Result<Vec<u8>, &'static str> {
        let mut buf = Vec::new();
        loop {
            let l = left(until).ok_or("timed out")?;
            let mut tmp = [0u8; 1024];
            let n = self.io(Op::Read(&mut tmp), l).ok_or(if left(until).is_none() { "timed out" } else { "closed" })? as usize;
            if n == 0 {
                return Err("closed");
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(i) = buf.iter().position(|&c| c == b'\n') {
                buf.truncate(i);
                return Ok(buf);
            }
            if buf.len() > cap {
                return Err("too long");
            }
        }
    }
}

fn left(until: Instant) -> Option<Duration> {
    until.checked_duration_since(Instant::now()).filter(|d| !d.is_zero())
}
