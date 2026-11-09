<p align="center">
  <img src="docs/images/banner.svg" alt="PIA Lite" width="860">
</p>

<p align="center">
  <a href="https://github.com/NicholasBly/PIALite/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/NicholasBly/PIALite/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://github.com/NicholasBly/PIALite/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/NicholasBly/PIALite?sort=semver"></a>
  <img alt="Platforms" src="https://img.shields.io/badge/platforms-Windows%2010%2F11%20%7C%20Linux-informational">
  <a href="LICENSE"><img alt="License: GPL-3.0" src="https://img.shields.io/badge/license-GPL--3.0-blue"></a>
</p>

**PIA Lite** is a small, fast tray app for [Private Internet Access](https://www.privateinternetaccess.com/) (PIA).
It replaces PIA's own window with a tray icon and a compact panel - connect, disconnect, pick a region, see your
status - and talks to PIA only through PIA's official command-line tool (`piactl`). PIA's VPN service, drivers,
kill switch and split tunnel keep working exactly as before.

On top of that you can **choose** extras when you install - nothing is forced on you:

| Feature | What it does |
|---|---|
| **Network guard** (kill switch) | A tiny background service that blocks the internet until the VPN is connected - from power-on, or always. Works next to PIA's own kill switch as a second, independent layer. |
| **Encrypted DNS** | Every DNS lookup goes over HTTPS to the provider *you* pick: Quad9, Cloudflare, AdGuard, Google, NextDNS (your own profile) or any DNS-over-HTTPS server. |
| **Hotel Wi-Fi login** | One click turns the VPN off for a few minutes so you can get past a hotel/airport login page, then everything comes back by itself. |
| **Updates** | The tray checks GitHub about once a day; one click installs a new release - only if its signature checks out - and keeps your features. |

> PIA Lite is an independent open-source project. It is **not affiliated with, endorsed by or supported by
> Private Internet Access**. You need a PIA subscription and PIA's own app installed.

<p align="center">
  <img src="docs/images/panels.png" alt="The PIA Lite panel: connected, disconnected, choosing a region" width="820">
</p>

---

## Contents

- [Download and install](#download-and-install)
- [Choosing features](#choosing-features)
- [Encrypted DNS providers](#encrypted-dns-providers)
- [Kill switch modes](#kill-switch-modes)
- [How it works](#how-it-works)
- [Updates](#updates)
- [Stuck offline?](#stuck-offline)
- [Uninstall](#uninstall)
- [Command line](#command-line)
- [Troubleshooting](#troubleshooting)
- [Building from source](#building-from-source)
- [Security](#security) - [Contributing](#contributing) - [License](#license)

## Download and install

Get the files from the **[latest release](https://github.com/NicholasBly/PIALite/releases/latest)**.
Install [PIA](https://www.privateinternetaccess.com/download) first and sign in to it once.

| System | File | How |
|---|---|---|
| Windows 10/11 (64-bit) | `PIALite-<version>-windows-x64.msi` | Double-click. The installer lets you pick features and your DNS provider. |
| Windows, no install | `PIALite-<version>-windows-x64-portable.zip` | Unzip anywhere, run `pialite-tray.exe`. Tray only (no guard). |
| Debian, Ubuntu, Mint, Pop!_OS | `pialite_<version>_amd64.deb` | `sudo apt install ./pialite_<version>_amd64.deb` |
| Fedora, RHEL, openSUSE | `pialite-<version>-1.x86_64.rpm` | `sudo dnf install ./pialite-<version>-1.x86_64.rpm` |
| Any Linux with systemd | `PIALite-<version>-linux-x86_64.tar.gz` | Unpack, then `sudo ./install.sh` - or run `bin/pialite-tray` as is (tray only). |

On Linux the packages only copy files. The **first time you open PIA Lite** (from your applications menu) it asks
which features you want - or run `sudo pialite-guard setup -i` in a terminal.

<details>
<summary><b>Silent / scripted install on Windows</b></summary>

```bat
msiexec /i PIALite-0.9.0-windows-x64.msi /qn DNS_PROVIDER=quad9 BLOCK_MODE=startup
msiexec /i PIALite-0.9.0-windows-x64.msi /qn ADDLOCAL=Main,Guard,Dns DNS_PROVIDER=nextdns NEXTDNS_ID=abc123
```

| Property | Values |
|---|---|
| `DNS_PROVIDER` | `quad9` (default), `cloudflare`, `adguard`, `google`, `nextdns` |
| `NEXTDNS_ID` | your NextDNS profile ID, with `DNS_PROVIDER=nextdns` |
| `BLOCK_MODE` | `startup` (default), `always`, `off` |
| Features (`ADDLOCAL` / `REMOVE`) | `Main` (always), `Guard`, `Dns`, `Hotel`, `Autostart`, `HidePia` |

</details>

<details>
<summary><b>Coming from a pre-0.9 build (PowerShell installer)?</b></summary>

Just install the MSI. It takes over the existing guard service and its settings (NextDNS profile, block mode),
and the new tray removes the old copy from your profile and its startup entry the first time it starts.

</details>

## Choosing features

<img align="right" src="docs/images/features.png" alt="The features window" width="360">

- **Windows:** the installer shows a feature tree, then a page for the DNS provider and the kill switch mode.
  To change your choice later: *Settings > Apps > PIA Lite > Modify* - or *Features and DNS provider...* in the
  tray menu, which opens the same screens.
- **Linux:** the features window (right) opens the first time you start PIA Lite, and from the tray menu
  any time later. It asks for your password (polkit) to apply. In a terminal: `sudo pialite-guard setup -i`.

Whatever you pick is written to an install record, so **updates install the same features** again.

| Option | Needs | Default |
|---|---|---|
| Network guard (kill switch) | - | on, mode *startup* |
| Encrypted DNS | guard | on, Quad9 |
| Hotel Wi-Fi login | guard | on |
| Start at sign-in | - | on |
| Don't start PIA's own window (Windows) | - | on - saves about 160 MB; PIA's VPN service still runs |

<br clear="right">

## Encrypted DNS providers

| Provider | Choose it for | Server |
|---|---|---|
| **Quad9** | privacy-focused non-profit, blocks known malware domains | `dns.quad9.net` (DNS over TLS - Quad9 ended DNS over HTTPS/1.1 in Dec 2025) |
| **Cloudflare** | speed | `cloudflare-dns.com` |
| **AdGuard** | blocks ads and trackers | `dns.adguard-dns.com` |
| **Google** | Google Public DNS | `dns.google` |
| **NextDNS** | your own filter lists, logs and parental controls (needs a free/paid NextDNS profile ID) | `dns.nextdns.io/<your id>` |
| **Custom** | any DNS-over-HTTPS server (command line: `set-dns custom https://host/dns-query IP[,IP]`) | yours |

The guard connects to the provider by IP address (no plain-DNS lookup ever happens to find it) and checks its TLS
certificate. Lookups go over HTTPS (DoH), or over TLS on port 853 (DoT) for Quad9. Switch any time: `pialite-guard set-dns cloudflare` (admin), or the features window.

- **Windows:** PIA's DNS setting is pointed at the guard (`127.0.0.1`); your previous setting is saved and put back
  on uninstall. If the NextDNS Windows app is installed, it is paused (not removed) so two DNS programs don't fight.
- **Linux:** the guard redirects every program's plain DNS (port 53) to itself with an nftables rule - whatever
  your distribution uses for DNS (systemd-resolved, NetworkManager, resolv.conf). PIA's own lookups are left alone.

## Kill switch modes

| Mode | Blocks the internet... | Good for |
|---|---|---|
| **Startup** *(default)* | from power-on until the VPN connects the first time; after that PIA's own kill switch takes over | most people - closes the gap before PIA is running |
| **Always** | whenever the VPN is not connected, at any time | maximum strictness |
| **Off** | never (the guard still does encrypted DNS / hotel login) | you only want the other features |

What always gets through: PIA itself (so it can connect), DHCP (getting an IP address) and - if PIA's *Allow LAN*
is on - your local network, but never plain DNS to your router. Change the mode from the tray (*Block internet*);
making it weaker asks for administrator rights.

Under the hood: **Windows Filtering Platform** filters (boot-time + persistent + a temporary "allow" that only
exists while the guard runs, so a crashed guard fails closed) and **nftables** on Linux (a table loaded before the
network starts at boot, plus the same fail-closed allow rule). Every rule is read back and compared with the plan
every 30 seconds - see [docs/DESIGN.txt](docs/DESIGN.txt).

## How it works

```mermaid
flowchart LR
  subgraph you[" "]
    tray["PIA Lite tray<br/>icon + panel"]
  end
  subgraph pia["Private Internet Access"]
    piactl["piactl"] --> svc["PIA service<br/>(VPN tunnel)"]
  end
  subgraph guard["PIA Lite guard (optional service)"]
    ks["Kill switch<br/>WFP / nftables"]
    proxy["DNS proxy<br/>127.0.0.1:53"]
    hotel["Hotel login"]
  end
  tray -- "connect / regions / status" --> piactl
  tray -- "status, modes<br/>(local pipe / socket)" --> guard
  guard -- "watches the VPN state" --> piactl
  apps["Your apps"] -- "DNS" --> proxy
  proxy -- "DNS over HTTPS" --> dns[("Quad9 / Cloudflare /<br/>AdGuard / Google / NextDNS")]
  ks -. "nothing but PIA gets out<br/>until the VPN is up" .- apps
```

- **pialite-tray** - the tray icon and panel (Rust + [Slint](https://slint.dev), CPU-rendered, no web engine).
  Runs as you, with no special rights.
- **pialite-guard** - the optional background service (Windows service / systemd unit), plus the `setup`,
  `teardown` and `apply-update` commands that every installer uses. Only administrators (Windows) or root and
  members of the `pialite` group (Linux) can talk to it; anything that weakens protection needs an administrator.

## Updates

About once a day (and never in the first minute and a half after sign-in) the tray asks GitHub whether a newer
release exists. If so, the menu and the panel show **Install update x.y.z**:

1. you click it and confirm the administrator / password prompt;
2. the guard downloads the package for *your* kind of install (MSI, .deb, .rpm or .tar.gz) into an admin-only folder;
3. it checks the file against `SHA256SUMS`, whose **ed25519 signature** must match the key built into PIA Lite
   ([keys/release-signing.pub](keys/release-signing.pub)) - otherwise nothing is installed;
4. the installer runs with your current features, and PIA Lite restarts.

The portable versions just point you to the download page. To turn the check off, set the environment variable
`PIALITE_NO_UPDATE_CHECK=1`. From a terminal: `pialite-guard check-update` / `pialite-guard apply-update` (admin).

## Stuck offline?

The kill switch is designed to fail closed, so if something goes wrong you may have no internet until the VPN
connects. To turn the block off right away:

- **Windows:** Start menu > *PIA Lite* > **Unlock Internet** (asks for administrator rights).
- **Linux:** `sudo pialite-guard unlock`

Turn it back on later from the tray. `pialite-guard status` and `pialite-guard show-rules` show what is going on.

## Uninstall

- **Windows:** *Settings > Apps > PIA Lite > Uninstall*. The block rules are removed (and checked), PIA's DNS
  setting and kill switch are put back, and PIA's own window starts at sign-in again.
- **Debian/Ubuntu:** `sudo apt remove pialite` (`purge` also deletes the settings).
- **Fedora/openSUSE:** `sudo dnf remove pialite`
- **tar.gz:** from the unpacked folder, `sudo ./install.sh --uninstall`.

## Command line

`pialite-guard` without arguments lists every command. The most useful:

```text
pialite-guard status                 what the guard is doing
pialite-guard mode startup           block mode: off | startup | always
pialite-guard hotel start            hotel Wi-Fi login (VPN off for a few minutes)
pialite-guard features               what is installed
pialite-guard setup -i               (admin) choose features again, asking in the terminal
pialite-guard set-dns quad9          (admin) switch the encrypted DNS provider
pialite-guard test-dns               (admin) prove lookups go through the guard, encrypted
pialite-guard show-rules             (admin) every firewall rule, checked against the plan
pialite-guard unlock                 (admin) emergency: block off
```

## Troubleshooting

<details>
<summary><b>Linux: no tray icon (GNOME)</b></summary>

PIA Lite uses the standard StatusNotifierItem tray protocol. KDE, Cinnamon, XFCE, MATE, Budgie and most others
show it out of the box; on **GNOME** install the *AppIndicator and KStatusNotifierItem Support* extension
(Ubuntu ships it enabled).
</details>

<details>
<summary><b>Linux: encrypted DNS says "not listening"</b></summary>

Another program already uses `127.0.0.1:53` - usually `dnsmasq` (libvirt, some NetworkManager setups) or a local
resolver. `sudo ss -lunp 'sport = :53'` shows which one. Until the port is free the guard leaves your DNS alone
(it only redirects lookups while its proxy is actually listening).
</details>

<details>
<summary><b>The panel opens in the wrong place</b></summary>

On Windows it opens above the tray. On Linux it opens at the top-right of the screen; under Wayland the compositor
decides where windows go.
</details>

<details>
<summary><b>Logs</b></summary>

- Guard: `C:\ProgramData\PiaLite\guard.log` / `/var/lib/pialite/guard.log`
- Tray: `%LOCALAPPDATA%\PiaLite\tray.log` / `~/.local/state/pialite/tray.log`
- Windows installer: `msiexec /i PIALite-....msi /l*v install.log`
</details>

## Building from source

Requirements: [Rust](https://rustup.rs) (stable). Linux also needs `libfontconfig1-dev` (Debian/Ubuntu) or
`fontconfig-devel` (Fedora).

```sh
cargo build --release          # target/release/pialite-tray and pialite-guard
cargo test --workspace         # unit tests (no admin rights, no PIA needed)
sudo unshare --net target/release/pialite-guard selftest-firewall   # Linux: real nftables, isolated
```

Packages: `packaging/linux/build-packages.sh <version>` (needs `dpkg-deb`, and `rpmbuild` for the .rpm) and
`packaging/windows/build.ps1 -Version <version>` (needs the [WiX Toolset](https://wixtoolset.org) v5).
Releases are built by GitHub Actions when a `v*` tag is pushed - see [.github/workflows](.github/workflows).
The Windows release test kit is in [tests/windows](tests/windows) and [docs/RELEASE-CHECKLIST.md](docs/RELEASE-CHECKLIST.md).

## Security

Please report vulnerabilities privately - see [SECURITY.md](SECURITY.md). Design notes and the full history of
independent reviews and fixes: [docs/DESIGN.txt](docs/DESIGN.txt), [docs/AUDIT-RESPONSE.txt](docs/AUDIT-RESPONSE.txt).

## Contributing

Bug reports and pull requests are welcome - see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[GPL-3.0-or-later](LICENSE). "Private Internet Access" and "PIA" are trademarks of their owner; PIA Lite only
uses the name to say what it works with.
