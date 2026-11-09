//! PIA's command-line tool, through the shared runner (time limits, monitors).

pub use pialite_common::piactl::{is_shutdown, monitor, shutdown, T_CONNECT, T_GET, T_REGIONS, T_SET};

pub fn exe() -> std::path::PathBuf {
    pialite_common::piactl::exe()
}

/// Run piactl with the time limit that fits the command.
pub fn run(args: &[&str]) -> Result<String, String> {
    let limit = match args.first().copied() {
        Some("connect") | Some("disconnect") => T_CONNECT,
        Some("set") => T_SET,
        Some("get") if args.get(1) == Some(&"regions") => T_REGIONS,
        _ => T_GET,
    };
    pialite_common::piactl::run(args, limit)
}

/// Big status text for the panel header.
pub fn header_text(state: Option<&str>) -> String {
    match state {
        None => "PIA SERVICE NOT RUNNING".into(),
        Some("Connected") => "CONNECTED".into(),
        Some("Disconnected") => "DISCONNECTED".into(),
        Some("Connecting") | Some("StillConnecting") => "CONNECTING...".into(),
        Some("Reconnecting") | Some("StillReconnecting") | Some("DisconnectingToReconnect") => "RECONNECTING...".into(),
        Some("Interrupted") => "CONNECTION LOST - RETRYING".into(),
        Some("Disconnecting") => "DISCONNECTING...".into(),
        Some(other) => other.to_uppercase(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headers() {
        assert_eq!(header_text(Some("Connected")), "CONNECTED");
        assert_eq!(header_text(Some("StillConnecting")), "CONNECTING...");
        assert_eq!(header_text(None), "PIA SERVICE NOT RUNNING");
        assert_eq!(header_text(Some("SomethingNew")), "SOMETHINGNEW");
    }
}
