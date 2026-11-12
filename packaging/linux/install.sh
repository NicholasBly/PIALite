#!/bin/sh
# PIA Lite installer for the .tar.gz (any Linux distribution with systemd).
#
#   sudo ./install.sh              install - asks which features you want
#   sudo ./install.sh --upgrade    install this version, keep your features
#   sudo ./install.sh --uninstall  remove PIA Lite (block rules, service, files)
#
# Just want the tray, without installing anything? Run ./bin/pialite-tray
# from this folder (needs PIA's app; no kill switch / encrypted DNS then).
set -e
PREFIX=/opt/pialite
HERE=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" != 0 ]; then
    echo "Please run with sudo:  sudo $0 $*" >&2
    exit 1
fi

# Is anything of PIA Lite's still active in the system? (rules, saved boot
# rules, units) - printed, so the user sees what is left.
leftovers() {
    found=1
    for t in pialite pialite_dns; do
        if command -v nft >/dev/null 2>&1 && nft list table inet "$t" >/dev/null 2>&1; then
            echo "  - nftables table inet $t"; found=0
        fi
    done
    [ -f /var/lib/pialite/firewall.nft ] && { echo "  - saved boot rules /var/lib/pialite/firewall.nft"; found=0; }
    if systemctl is-enabled pialite-guard.service >/dev/null 2>&1 || systemctl is-active pialite-guard.service >/dev/null 2>&1; then
        echo "  - the guard service pialite-guard.service (enabled or running)"; found=0
    fi
    # the boot unit stays "active" after its one run at boot: only enabled counts
    if systemctl is-enabled pialite-boot.service >/dev/null 2>&1; then
        echo "  - the boot unit pialite-boot.service (enabled)"; found=0
    fi
    return $found
}

by_hand() {
    echo "By hand (as root), then run this again:" >&2
    echo "  systemctl disable --now pialite-guard.service pialite-boot.service" >&2
    echo "  nft delete table inet pialite; nft delete table inet pialite_dns" >&2
    echo "  rm -f /var/lib/pialite/firewall.nft" >&2
}

uninstall() {
    if [ -x "$PREFIX/bin/pialite-guard" ]; then
        "$PREFIX/bin/pialite-guard" teardown || {
            echo "Could not remove the block rules - run: sudo $PREFIX/bin/pialite-guard unlock" >&2
            exit 1
        }
    elif leftovers; then
        # the program that removes them is gone: never report a clean removal
        # with rules still in place (review V95-05) - nothing is deleted here
        echo "PIA Lite's program ($PREFIX/bin/pialite-guard) is missing, but these are still active (listed above)." >&2
        echo "Easiest: extract the same PIA Lite version again and run its install.sh --uninstall." >&2
        by_hand
        exit 1
    fi
    rm -f /usr/local/bin/pialite-tray /usr/local/bin/pialite-guard
    rm -f /usr/local/share/applications/pialite.desktop
    rm -f /usr/local/share/icons/hicolor/scalable/apps/pialite.svg
    rm -f /etc/xdg/autostart/pialite-tray.desktop
    rm -rf "$PREFIX"
    systemctl daemon-reload >/dev/null 2>&1 || true
    if leftovers; then
        echo "PIA Lite's files are removed, but the items above are still active." >&2
        by_hand
        exit 1
    fi
    echo "PIA Lite removed."
}

case "$1" in
    --uninstall) uninstall; exit 0 ;;
    --upgrade|"") ;;
    *) echo "unknown option: $1 (use --upgrade or --uninstall)" >&2; exit 1 ;;
esac

if ! command -v systemctl >/dev/null 2>&1; then
    echo "PIA Lite's guard needs systemd. You can still run the tray alone: ./bin/pialite-tray" >&2
    exit 1
fi

# the old guard stops before its program is replaced
systemctl stop pialite-guard.service >/dev/null 2>&1 || true
install -d -m 0755 "$PREFIX" "$PREFIX/bin" "$PREFIX/share" "$PREFIX/share/pialite"
install -m 0755 "$HERE/bin/pialite-tray" "$HERE/bin/pialite-guard" "$PREFIX/bin/"
printf 'tarball\n' > "$PREFIX/share/pialite/install-kind"
install -d /usr/local/bin /usr/local/share/applications /usr/local/share/icons/hicolor/scalable/apps
ln -sf "$PREFIX/bin/pialite-tray" /usr/local/bin/pialite-tray
ln -sf "$PREFIX/bin/pialite-guard" /usr/local/bin/pialite-guard
sed "s|^Exec=.*|Exec=$PREFIX/bin/pialite-tray|" "$HERE/share/pialite.desktop" > /usr/local/share/applications/pialite.desktop
install -m 0644 "$HERE/share/pialite.svg" /usr/local/share/icons/hicolor/scalable/apps/pialite.svg

if [ "$1" = "--upgrade" ] && [ -f /var/lib/pialite/install.json ]; then
    "$PREFIX/bin/pialite-guard" setup --kind tarball
else
    "$PREFIX/bin/pialite-guard" setup --kind tarball --interactive
fi
echo
echo "Start the tray from your applications menu ('PIA Lite') or run: pialite-tray"
