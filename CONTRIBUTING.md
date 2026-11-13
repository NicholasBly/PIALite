# Contributing to PIA Lite

Thanks for helping! Bug reports, test results from real machines and pull requests are all welcome.

## Reporting bugs

Open an issue with the *Bug report* template. The most useful things to include:

- PIA Lite version (`pialite-guard version`), operating system, PIA version and protocol (WireGuard / OpenVPN)
- what you did, what you expected, what happened
- `pialite-guard status` and the end of the logs (guard: `C:\ProgramData\PiaLite\guard.log` or
  `/var/lib/pialite/guard.log`; tray: `%LOCALAPPDATA%\PiaLite\tray.log` or `~/.local/state/pialite/tray.log`)

Please remove personal details (user names, public IP, NextDNS profile ID) before posting.
Security problems: see [SECURITY.md](SECURITY.md) instead.

## Development

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
sudo unshare --net target/debug/pialite-guard selftest-firewall   # Linux, real nftables in a throwaway namespace
sudo sh tests/install-sh-uninstall.sh                             # Linux, install.sh's uninstall checks (fake tools)
sudo sh tests/install-sh-upgrade.sh                               # Linux, install.sh's upgrade rollback (fake tools)
sudo sh tests/isolate-preflight.sh                                # Linux, the two above refuse where a folder is missing
# (the install.sh tests run in their own mount namespace, with /opt, /usr/local, /var/lib, /run, /tmp and the unit
#  folders hidden - safe next to a real installation; they refuse to run if they can't isolate themselves, or
#  if a folder they write under is missing. isolate-preflight checks that in throwaway read-only roots.)
```

`selftest-firewall` replaces PIA Lite's real firewall rules: on Windows it refuses to run where PIA Lite is
set up (CI runners only; `--force` overrides). The Rust version is pinned in `rust-toolchain.toml`; raise it in
its own commit.

The workspace has three crates:

| Crate | What |
|---|---|
| `pialite-tray` | tray icon, panel and features window (Slint UI in `ui/app.slint`) |
| `pialite-guard` | the background service plus `setup`, `teardown`, updates and checks |
| `pialite-common` | shared code: piactl runner, status types, the control channel client |

Guidelines that keep this project trustworthy:

- **Fail closed.** If the guard can't tell whether something is safe, it blocks (and says why).
- **Read back what you change.** Firewall rules, PIA settings and files are checked after they are written.
- **Tests for behaviour.** A fix comes with a test that fails without it. The firewall has an in-memory stand-in
  for unit tests; `selftest-firewall` and CI exercise the real one.
- **Plain messages.** Anything a user sees should say what happened and what to do, without jargon.
- Platform code goes behind `cfg(windows)` / `cfg(target_os = "linux")`; tests must pass on both (CI runs both).

## Releases

1. Update the version in the three `Cargo.toml` files and add a section to `CHANGELOG.md`.
2. Run the Windows release test kit (`tests/windows/Run-Phase5.bat`) and the checklist in
   [docs/RELEASE-CHECKLIST.md](docs/RELEASE-CHECKLIST.md).
3. Push the version bump to `main`. GitHub Actions sees a version without a release, builds and tests it,
   signs `SHA256SUMS`, creates the tag `vX.Y.Z` and publishes the release. (Pushing a tag works too.)

By contributing you agree that your contributions are licensed under the GPL-3.0-or-later.
