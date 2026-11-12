# Changelog

All notable changes to PIA Lite. Versions follow [semantic versioning](https://semver.org).

## [0.9.8] - 2026-11-12

Fixes from the independent v0.9.7 review (G97-01 .. G97-09). **The first signed release.**

### Fixed
- **Turning the guard feature off uses the same protected order as uninstalling** (G97-01): the guard is
  stopped, its DNS redirect and block removed and checked, and only then is the service removed - a failed step
  brings the guard back instead of leaving rules with nobody to look after them.
- **"The guard is back" is said only when it is seen** (G97-02): after a failed removal step the guard is
  started again and must answer with the version, block mode, armed block and DNS block it had before (or, if
  it wasn't running, with its block in place); otherwise the message says protection could NOT be confirmed and
  how to unlock. It is also started again when it wasn't running before - a half-removed block is worse.
- **Windows: a damaged DNS block is replaced without a gap** (G97-03): the new block is built and checked next
  to the old one (two sublayer keys used in turn), and only then is the old one dropped; if the new one can't
  be built, what is left of the old one stays. The firewall self-test makes a rebuild fail on purpose and checks
  the old block still stops a lookup.
- **Windows: a program that can't be put in a job object is logged and named in timeout errors** (G97-04), so
  "everything it started was stopped" is never claimed without it.
- **install.sh --upgrade keeps the previous version until the new one is set up** (G97-05): a guard that won't
  stop means nothing is replaced; a failed setup puts the previous programs back and starts the previous guard.
  Tested in CI with fake tools.
- **Start menu shortcuts** point at the programs by folder and name (WiX ICE69, G97-07); CI now checks both
  shortcuts after installing and that they are gone after uninstalling, and fails on any ICE warning.
- CI: the package/MSI removal runs only after an install was started (the first failure stays the one
  reported), and "nftables / systemd can't be asked" fails the check instead of passing it (G97-08).

### Changed
- **Releases must be signed** (G97-06): without the signing key the publish job fails. Before publishing it
  runs the packaged `pialite-guard verify-release` (the updater's own check, with the key built into the
  program) on the release, and makes sure it refuses a tampered package. New command:
  `pialite-guard verify-release FOLDER`.

## [0.9.7] - 2026-11-12

Fixes from the independent v0.9.6 review (F-01 .. F-10).

### Fixed
- **setup checks the running guard is the one it just installed** (F-01): this version, the block mode just saved
  (exactly - Always asked and Off running is a failure, so is a stronger mode than asked), and that mode's block
  in place. Before, a guard reporting Off passed whatever was asked.
- **Teardown keeps the PC usable if a step fails** (F-02): the DNS redirect is removed (and checked) first, then
  the block - boot unit, saved rules, and the live rules last. If any step fails, the guard is started again, so
  its block and DNS are back as before, and the message says what state the PC is in.
- **Windows DNS block: every rule is checked, not just its sublayer** (F-03): each rule by its id (layer,
  sublayer, action, weight, flags, every condition) and nothing extra in the sublayer. A damaged block is
  reported as not on and rebuilt. The Windows firewall self-test deletes a rule and adds a stray permit, and
  expects both to be noticed and repaired.
- **Linux: "systemd couldn't be asked" is not "stopped"** (F-04): teardown stops instead of touching the firewall.
- **Programs that setup/teardown run are stopped with everything they started** (F-05): own process group (Linux)
  / job object (Windows), killed as a whole at the time limit; a program it started that keeps the output open
  no longer makes the wait endless. The limit now counts from before the program starts.
- **Linux data files** (F-06): settings and records are created 0600 whatever the umask (install.json stays 0644
  for the tray); setup refuses links and hard-linked files in the data folder and gives everything in it to root,
  with no write access for others.
- **Windows: links, junctions and mount points** anywhere on the guard program's path are refused (F-07).
- **install.sh --uninstall says "removed" only when it could check** (F-08): nft or systemd missing or not
  answering is "can't check", not "nothing left"; unit files count; the check runs before the last program that
  could remove the rules is deleted. A test with fake nft/systemctl covers it in CI.

### Changed
- The Rust version is pinned (`rust-toolchain.toml`, 1.97.0) and printed in the build logs; live DNS-provider
  probes run on pushes and releases, not on pull requests (F-10).

## [0.9.6] - 2026-11-12

Fixes from the independent v0.9.5 review (V95-xx).

### Fixed
- **The DNS block / redirect is reported only when the firewall confirmed it** (V95-01, V95-11). A failed add,
  remove or check leaves it "not known": `status` says "Other DNS : NOT blocked - <why>", it is tried again after
  10 s, and stopping the guard removes it unless it is known to be off. The reason is shown when it is off (VPN
  not connected / PIA's DNS not applied, proxy not listening, adapters unreadable).
- **Linux: a guard that didn't stop stops teardown** (V95-02): `systemctl stop` failing, or the service still
  running after 30 s, is an error before any firewall rule is touched; `disable` failures are no longer ignored.
- **Teardown checks the Linux DNS redirect is gone** before removing anything else (V95-17); a failed boot-unit
  `disable` is reported instead of ignored (V95-12).
- **Windows folder permissions are set and checked as a whole** (V95-03): the data folder and a custom MSI folder
  get their entire access list replaced (Administrators owner; SYSTEM + Administrators full, Users read; nothing
  else kept - `icacls /grant:r` kept other accounts' entries), and setup refuses to register the SYSTEM service if
  any other account could replace the program, change its folder or move a folder above it away - Program Files
  included (checked, not assumed).
- **setup fails when the guard doesn't answer or can't put the chosen block in place** (V95-06) - before, that
  was a warning in the installer log. A .deb/.rpm upgrade whose setup fails now fails too (V95-09).
- **`selftest-firewall` refuses to run on a PC where PIA Lite is set up** (Windows; it replaces the real rules) -
  `--force` overrides (V95-04).
- **install.sh --uninstall with the program missing** no longer says "removed" while rules, the saved boot rules
  or the units are still active: it lists them, explains how to remove them and stops (V95-05).
- Programs run by setup/teardown have a 2-minute limit (10 for package installs) and capped output; each update
  download connection only gets what is left of its 120 s (V95-10).

### Changed
- **Releases are published only from a fully passing CI run** (V95-13): the release workflow runs the whole CI
  workflow (format, clippy, tests, real WFP/nftables self-tests, a real MSI and .deb install/uninstall) and
  publishes exactly the packages that CI built and installed, after checking the file list. Only the publish job
  can write to the repository; actions are pinned to commit SHAs; unsigned releases say so in their notes
  (V95-14, V95-15, V95-16).

## [0.9.5] - 2026-11-12

### Added
- **Windows: DNS to other servers is blocked while the VPN is connected** (plain DNS on port 53 and DNS over TLS on
  853), so nothing goes around the guard - a program asking 8.8.8.8 itself, Windows asking another adapter's DNS
  server, VMs sharing the PC's connection. Allowed: loopback (the guard's proxy), PIA's programs, the guard. It is on
  only while Windows really sends lookups to the guard (PIA's adapter has 127.0.0.1 as its DNS) and the proxy is
  listening, in a temporary firewall session that Windows removes by itself if the guard stops - it can't leave the
  PC without DNS. `status` shows it ("Other DNS"); the firewall self-test checks it on a real Windows machine.

### Changed
- `status` / `set-dns` say "over TLS" for servers reached that way (Quad9, `tls://` servers) - it said HTTPS.
- "your DoH server" is now "your DNS server" (custom servers can be DNS over TLS too).
- `test-dns` on Windows: when Windows doesn't use the guard yet, it says to reconnect PIA (PIA applies its DNS
  setting when it connects).

## [0.9.4] - 2026-11-12

### Added
- The installer's last page has a ticked "Start PIA Lite now" box, so the tray starts right after installing.

### Fixed
- `adapter-dns` / setup no longer warn that port 53 is taken when the guard is already listening on it, or on
  Windows when only a program on the wildcard address holds it (Internet Connection Sharing for Hyper-V, inside
  svchost) - that doesn't stop the guard. Seen on a real PC. Port-53 holders are shown as "program on address".

## [0.9.3] - 2026-11-12

### Fixed
- The DNS conflict check skips a network card bound to a Hyper-V virtual switch: it has no IP of its own, so
  old DNS settings left on it aren't used (the vEthernet adapter is the one that counts).
- `tools/dns-report.ps1`: section headings were missing (`H` is PowerShell's alias for Get-History), the TLS
  certificate check failed in PowerShell 7, and programs on port 53 inside `svchost` are now named by service.

## [0.9.2] - 2026-11-11

### Fixed
- The DNS conflict check no longer reports a program that holds port 53 only on another address (e.g.
  Docker's DNS on its own network) - only one that blocks the proxy's 127.0.0.1:53 counts. Found by CI on a
  real Windows machine.

## [0.9.1] - 2026-11-11

### Added
- **Your own DNS server, e.g. a Pi-hole at home**, encrypted: custom servers can now be `tls://host[:port]`
  (DNS over TLS) as well as `https://host[:port]/path`, and can be trusted through their own certificate
  authority (`set-dns custom tls://pi.hole IP CA-FILE`, `setup --doh-ca FILE`). Guide: `docs/PIHOLE.md`.
- **DNS conflict check** in setup and `pialite-guard adapter-dns`: DNS typed in by hand on Windows network
  adapters (incl. Windows' own DNS over HTTPS), other DNS programs (YogaDNS, dnscrypt-proxy, AdGuard, ...),
  anything holding port 53, systemd-resolved's own DNS over TLS. `adapter-dns --reset` sets adapters back to
  automatic (put back on uninstall).
- Setup warns when a home DNS server can't be reached while connected because PIA's "Allow LAN" is off.
- `tools/dns-report.ps1` (Windows) and `tools/pihole-report.sh` (Pi-hole): read-only reports of a DNS setup.

### Changed
- The "is DNS routed through the VPN" note is skipped for a server on your own network (it never is, by design).
- GitHub Actions updated (checkout v7, upload-artifact v7, download-artifact v8).

## [0.9.0] - 2026-11-09

First public release. Earlier versions (0.1 - 0.6.5) were private builds for one PC, installed with
PowerShell scripts; they went through ten rounds of independent review.

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
