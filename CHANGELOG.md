# Changelog

All notable changes to PIA Lite. Versions follow [semantic versioning](https://semver.org).

## [0.9.0] - 2026-11-09

First public release. Earlier versions (0.1 - 0.6.5) were private builds for one PC, installed with
PowerShell scripts; they went through ten rounds of independent review (see `docs/AUDIT-RESPONSE.txt`).

### Added
- **Choose your features.** The kill switch (network guard), encrypted DNS and the hotel Wi-Fi login are each
  optional; the tray alone works without any of them. Every installer runs the same `pialite-guard setup`,
  so all of them install exactly what was chosen, and updates keep it.
- **Any encrypted DNS provider:** Quad9, Cloudflare, AdGuard, Google, NextDNS (your profile) or your own
  DNS-over-HTTPS server. `pialite-guard set-dns` switches it. Quad9 is reached over DNS over TLS
  (port 853), since Quad9 no longer answers DNS over HTTPS/1.1.
- **Windows installer (MSI)** with a feature tree and a page for the DNS provider and kill switch mode;
  silent installs with `DNS_PROVIDER`, `NEXTDNS_ID`, `BLOCK_MODE`. Start-menu shortcuts for PIA Lite and
  *Unlock Internet*. Uninstall removes the block rules (checked) and puts PIA's DNS, kill switch and startup back.
- **Windows portable zip** (tray only).
- **Linux:** the tray (StatusNotifierItem icon, X11 and Wayland) and the guard: an nftables kill switch loaded
  before the network starts at boot, encrypted DNS through a port-53 redirect that works with any resolver
  setup, hotel login, systemd services, polkit prompts. Packages: `.deb`, `.rpm`, `.tar.gz` with `install.sh`.
- **Features window** in the tray (first start on Linux; *Features and DNS provider...* in the menu).
- **Updates:** a daily check of GitHub releases; one click downloads the right package for your install,
  verifies it against the ed25519-signed `SHA256SUMS`, and installs it with your features.
- `pialite-guard selftest-firewall`: installs, checks and removes real firewall rules (Linux: in a separate
  network namespace) - run by CI on both systems.
- CI on Linux and Windows: formatting, Clippy, tests, the firewall self-test, package builds, and a real
  install / uninstall of the .deb and the MSI.

### Fixed (review of 0.6.5)
- V65-01: after a hotel login, the reconnect decision now uses the newest accepted VPN state, even when a newer
  report arrives while PIA is being asked.
- V65-02: a failed reconnect after a hotel login is retried (5 s, then 15 s; only if still needed) and, if it
  keeps failing, shown in the tray ("... - press Connect").
- V65-03: a Disconnect pressed in the tray is only ended by a *new* connection seen after it, not by an older
  cached state.
- V65-04: the tray decides "a guard is installed" from the service registration, not only from where the
  program file used to be.

### Changed
- Version 0.9.0. The PowerShell installers are replaced by the MSI (an existing guard service and its settings
  are taken over); the Windows release test kit moved to `tests/windows`.
- Messages say "the firewall" instead of "Windows" where both systems are meant.
