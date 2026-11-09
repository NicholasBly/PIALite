# Release checklist

A release is one build (the files GitHub Actions attached to the release, identified by `SHA256SUMS`), the
test reports below, and this list ticked off. Unit tests and CI can't prove there are no leaks on a real PC -
these runs are the evidence. Keep PIA's own kill switch **on** in normal use: it is a second, independent layer.

## 1. Automatic (CI must be green on the tagged commit)

- [ ] Linux: fmt, clippy, tests, `selftest-firewall` (real nftables), packages, real `.deb` install +
      `setup` + `test-dns` + removal leaving nothing behind
- [ ] Windows: clippy, tests, `selftest-firewall` (real WFP), MSI build + ICE validation, silent install +
      uninstall leaving nothing behind

## 2. Windows (on a real PC with PIA)

Install the MSI from the release, then run `tests/windows/Run-Phase5.bat`. Keep every report (its *Build:*
line names the exact programs tested). A FAIL, or an unexplained INCONCLUSIVE, stops the release.

- [ ] Option 1 (quick checks): rules, DNS, block test with PIA's kill switch off (guard alone), hotel login
- [ ] Always mode, PIA disconnected, network up: no IPv4 / IPv6 / DNS (UDP+TCP 53) gets out; connected:
      `pialite-guard test-dns` passes (NextDNS: its test page confirms DoH)
- [ ] Option 2 -> restart -> option 3 (startup leak test) with Ethernet plugged in, so *Protection before the
      guard started* can reach PASS
- [ ] Option 5 (capture self-check) on the same adapter
- [ ] Connect lifecycle: sleep/wake, Wi-Fi off/on, Disconnect in the tray (the guard must not reconnect by
      itself), a hotel login started and ended within seconds (the VPN comes back), a failed reconnect after a
      hotel login (the tray says *press Connect*)
- [ ] Installer: interactive install with each DNS provider choice; *Modify* (remove Encrypted DNS: PIA's DNS
      setting comes back); upgrade from the previous release keeps features; uninstall leaves no rules
      (`show-rules`), PIA's DNS and kill switch as before, PIA's window starts at sign-in again
- [ ] Tray: sign in right after a restart, restart Explorer, start PIA Lite a second time - exactly one icon
- [ ] Update: with a test release, *Install update* installs it and the tray comes back

## 3. Linux (on a real desktop with PIA)

On at least one Debian/Ubuntu and one Fedora machine:

- [ ] Install the package; first start shows the features window; Apply asks for the password and works
- [ ] Always mode, PIA disconnected: nothing gets out (`ping 1.1.1.1`, `curl https://example.com`, `dig @9.9.9.9`);
      connected: everything works and `sudo pialite-guard test-dns` passes
- [ ] Reboot with Always mode: no traffic before the VPN connects (`pialite-boot.service` active)
- [ ] Sleep/wake; Disconnect in the tray is respected; hotel login start/stop
- [ ] Tray icon on KDE and on GNOME (with the AppIndicator extension); panel opens; region change works
- [ ] Remove the package: no `pialite` nftables tables, DNS works normally
- [ ] tar.gz: `install.sh`, `install.sh --upgrade`, `install.sh --uninstall`

## 4. Known limitations (say them, don't hide them)

- No certified protection before the guard service starts on Windows: the boot-time and stored rules are
  there, but a PASS for that window needs the leak test with the conditions in 2.
- Why Windows once refused a rule refresh with "in use" (0x8032000A) is not known; the guard keeps working
  and logs the details.
- "PIA adapter observed up" is what the system reports, not a test of the encrypted tunnel.
- Linux: PIA's kernel WireGuard packets are let through by their firewall mark (taken from PIA's source);
  confirm on each PIA version. IPv6 DNS is refused while encrypted DNS is on (PIA blocks IPv6 anyway).
- Linux: the panel can't be placed next to the tray under Wayland (the compositor decides).
