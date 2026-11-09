//! Shared by the tray app and the guard service.
//!   piactl  - run PIA's command-line tool with time limits; monitor its state
//!   status  - the guard's status report (typed, versioned)
//!   ipc     - talk to the guard service (authenticated named pipe on Windows)
//!   logfile - small rotating log files with readable UTC timestamps
//!   winio   - (Windows) overlapped pipe I/O with hard time limits

pub mod ipc;
pub mod logfile;
pub mod piactl;
pub mod status;
#[cfg(windows)]
pub mod winio;
