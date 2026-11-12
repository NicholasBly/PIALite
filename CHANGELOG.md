# Changelog

All notable changes to PIA Lite. Versions follow [semantic versioning](https://semver.org).

## [0.9.11] - 2026-11-12

Fixes from the independent v0.9.10 review (R10-01 .. R10-06), and two requests.

### Added
- **Check for updates in the tray menu**: checks right away instead of waiting for the daily check. The line then
  says what the check found - "up to date: x.y.z", or "last check failed" (offline, GitHub didn't answer). A check
  that got no answer is never shown as "up to date". It also works with `PIALITE_NO_UPDATE_CHECK` set (that only
  turns off the daily check).
- **README: "How much lighter?"** - memory measured on a Windows 11 PC before and after (PIA's window + the NextDNS
  app: 187 MB private memory; PIA Lite: 22 MB), what that number means, CPU (close to zero either way), and which
  programs PIA Lite replaces.

### Fixed
- **The install.sh tests refuse where a folder they write under is missing** (R10-01): `/opt`, `/usr/local`,
  `/var/lib` and `/run` must exist and be reached without a link, or the test stops before anything runs (it
  would otherwise create that folder on the real system). Folders install.sh only deletes from may be missing;
  the tests check at the end that they still are. The tests' own paths are checked too. New
  `tests/isolate-preflight.sh` proves it in throwaway root filesystems (read-only binds of the system) with one
  folder missing at a time; it runs in CI.
- **An incomplete copy is never used to "restore"** (R10-02): the copy of the version in use is made in
  `/opt/pialite.rollback.part`, marked complete, written to disk and only then renamed to `/opt/pialite.rollback`.
  `--restore-previous` refuses an incomplete copy without stopping the guard; a copy left from before the guard
  was stopped is recognized ("nothing to put back") and removed instead of restored.
- **A failed stop is checked, not assumed** (R10-03): when `systemctl stop` fails, install.sh asks systemd for the
  guard's real state, starts it again if it did stop, and checks its protection like after a rollback. It now says
  "no program files were replaced" instead of "nothing was changed".
- **Only one installer at a time** (R10-04): install, `--upgrade`, `--uninstall` and `--restore-previous` take a
  lock (`flock` on `/run/pialite-install.lock`, which only root can create) before looking at anything; a second
  one stops with "Another PIA Lite install ... is running".
- **"PARTIALLY VERIFIED"** (R10-05): a rollback from a guard that didn't report its DNS block says so in those
  words, never "protects as before".

## [0.9.10] - 2026-11-12

Fixes from the independent v0.9.9 review (N99-01 .. N99-08).

### Fixed
- **The install.sh tests hide every real path install.sh can touch** (N99-01): `/etc/xdg/autostart` was not hidden,
  so the uninstall test could have removed a real tray autostart entry. The isolation is now a checked contract:
  every absolute path in install.sh must lie in a hidden folder, or the test refuses to run (and names the folder
  to add). CI puts a stand-in file at each of those real paths and checks they are all untouched afterwards.
- **Tests started from a namespace with shared mounts isolate themselves again** (N99-07): isolated now means our
  own namespace AND no shared mount; CI runs a test that way and checks nothing leaked out.
- **Tarball rollback checks the DNS block too** (N99-02): it records whether DNS went only through the guard
  before, and "protects as before" needs that back as well; otherwise "could NOT be confirmed".
- **A kept rollback copy is never overwritten** (N99-03): while one exists, install.sh changes nothing and points to
  the new `sudo ./install.sh --restore-previous` (also the way back after a power cut mid-upgrade).
- **Rollback checks its own steps** (N99-04): any restore step that fails (programs, share, settings, menu entry,
  icon, launchers, starting the guard) is named and the copy is kept; settings and menu files that didn't exist
  before are removed again; the menu entry and icon are restored from the copy.
- **An installed guard whose program isn't /opt/pialite** (e.g. a .deb) is not stopped by the tarball installer
  (N99-06) - it changes nothing and says to remove that one first.
- **Recovery after an unreadable earlier state also expects the saved DNS feature** (N99-05): a guard back with
  its block but without its DNS block / redirect isn't confirmed.

## [0.9.9] - 2026-11-12

Fixes from the independent v0.9.8 review (R98-01 .. R98-09).

### Fixed
- **The install.sh tests can't touch a real installation** (R98-01): they now run only in their own mount
  namespace, with /opt, /usr/local, /var/lib and the systemd unit folders replaced by empty tmpfs, and refuse
  to run otherwise (not root, no `unshare`, can't tell). Before, the upgrade test's cleanup could delete a real
  /opt/pialite. CI places a stand-in "real install" next to them and checks it is untouched afterwards.
- **Tarball upgrades are all-or-nothing** (R98-02, R98-06): the new version is staged and the version in use
  (programs, settings, and the block mode its guard reports) is copied *before* the guard is stopped; a failure
  at ANY later step - moving files, links, the menu entry, setup, Ctrl+C - puts the previous programs and
  settings back, starts the previous guard, and says "as before" only when it reports the same block mode with
  its block in place; otherwise "could NOT be confirmed", and the copy is kept. Tested with failures injected
  at every step.
- **Recovery never certifies protection it couldn't see** (R98-03): when the guard's earlier state can't be
  read, it is checked against the saved block mode, says so, and a guard that comes back in Off mode is
  "not confirmed".
- **Turning the guard off puts the previous settings back first if that fails** (R98-04), so the guard comes
  back as it was, not with the new mode; removing the service is retried once, and if it still fails the message
  says exactly what was removed and what is left (R98-05).
- **Windows DNS block rebuild: a failure at each stage** (opening the engine, adding the sublayer, adding a rule,
  checking the new block) is injected in the firewall self-test, which checks that UDP/53, TCP/53 and TCP/853
  from another program stay blocked by what is left of the old block (IPv4; hosted runners have no IPv6) (R98-07).
- CI uninstalls only what got installed and inspects either way (R98-08).

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
