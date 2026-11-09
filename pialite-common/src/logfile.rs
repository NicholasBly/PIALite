//! Tiny rotating log file: one line per call, UTC timestamp, rotates at `max_bytes`
//! (the previous file is kept as `<name>.old.log`).

use std::io::Write;
use std::path::Path;
use std::sync::Mutex;

static LOCK: Mutex<()> = Mutex::new(());

pub fn append(path: &Path, max_bytes: u64, msg: &str) {
    let _g = LOCK.lock();
    if let Some(dir) = path.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if std::fs::metadata(path).map(|m| m.len() > max_bytes).unwrap_or(false) {
        let _ = std::fs::rename(path, path.with_extension("old.log"));
    }
    let line = format!("{} {msg}\r\n", now_utc());
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(line.as_bytes());
    }
}

/// "YYYY-MM-DD HH:MM:SS.mmmZ" (milliseconds: the leak test lines up events precisely)
pub fn now_utc() -> String {
    let d = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
    let t = timestamp(d.as_secs());
    format!("{}.{:03}Z", t.trim_end_matches('Z'), d.subsec_millis())
}

/// UTC "YYYY-MM-DD HH:MM:SSZ" without a date crate.
pub fn timestamp(secs: u64) -> String {
    let days = (secs / 86400) as i64;
    let rem = secs % 86400;
    // civil-from-days (Howard Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn times() {
        assert_eq!(timestamp(0), "1970-01-01 00:00:00Z");
        assert_eq!(timestamp(1_793_000_000), "2026-10-26 07:33:20Z");
        assert_eq!(timestamp(951_782_400), "2000-02-29 00:00:00Z");
    }
}
