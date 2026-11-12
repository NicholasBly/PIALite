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
#   returns 0 = something is left, 1 = checked: nothing left,
#           2 = could NOT check (that is never "nothing left" - review F-08)
leftovers() {
    found=1
    if ! command -v nft >/dev/null 2>&1; then
        echo "  ? nftables (nft) is not installed - the firewall rules can't be checked" >&2; return 2
    fi
    if ! tables=$(nft list tables 2>&1); then
        echo "  ? the firewall rules can't be read: $tables" >&2; return 2
    fi
    for t in pialite pialite_dns; do
        if printf '%s\n' "$tables" | grep -qx "table inet $t"; then
            echo "  - nftables table inet $t"; found=0
        fi
    done
    [ -e /var/lib/pialite/firewall.nft ] && { echo "  - saved boot rules /var/lib/pialite/firewall.nft"; found=0; }
    for d in /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
        for u in pialite-guard.service pialite-boot.service; do
            [ -e "$d/$u" ] && { echo "  - unit file $d/$u"; found=0; }
        done
    done
    if ! command -v systemctl >/dev/null 2>&1; then
        echo "  ? systemd (systemctl) is not available - the services can't be checked" >&2; return 2
    fi
    for u in pialite-guard.service pialite-boot.service; do
        # "inactive"/"failed" = not running; anything else, or no answer, counts
        state=$(systemctl show --property=ActiveState --value "$u" 2>&1) || {
            echo "  ? systemd can't be asked about $u: $state" >&2; return 2
        }
        enabled=$(systemctl is-enabled "$u" 2>/dev/null || true)
        case "$enabled" in enabled|enabled-runtime|static|linked|linked-runtime|alias|indirect|generated|transient)
            echo "  - $u is $enabled"; found=0 ;;
        esac
        # the boot unit stays "active" after its one run at boot: only its being enabled counts
        if [ "$u" = pialite-guard.service ] && [ "$state" != inactive ] && [ "$state" != failed ]; then
            echo "  - $u is $state"; found=0
        fi
    done
    return $found
}

by_hand() {
    echo "By hand (as root), then run this again:" >&2
    echo "  systemctl disable --now pialite-guard.service pialite-boot.service" >&2
    echo "  nft delete table inet pialite; nft delete table inet pialite_dns" >&2
    echo "  rm -f /var/lib/pialite/firewall.nft /etc/systemd/system/pialite-guard.service /etc/systemd/system/pialite-boot.service" >&2
}

# 0 when it is checked that nothing is left; otherwise explains and returns 1
verified_clean() {
    rc=0; leftovers || rc=$?
    case $rc in
        1) return 0 ;;
        2) echo "PIA Lite can't check that its firewall rules and services are gone (see above) - nothing more is removed." >&2 ;;
        *) echo "These are still active (listed above)." >&2 ;;
    esac
    by_hand
    return 1
}

uninstall() {
    if [ -x "$PREFIX/bin/pialite-guard" ]; then
        "$PREFIX/bin/pialite-guard" teardown || {
            echo "Could not remove the block rules - run: sudo $PREFIX/bin/pialite-guard unlock" >&2
            exit 1
        }
    else
        echo "PIA Lite's program ($PREFIX/bin/pialite-guard) is missing - checking what is left..." >&2
        echo "(Easiest if anything is: extract the same PIA Lite version again and run its install.sh --uninstall.)" >&2
    fi
    # checked BEFORE the last program that could remove them is deleted:
    # never "removed" with rules or services still there, or unchecked
    verified_clean || exit 1
    rm -f /usr/local/bin/pialite-tray /usr/local/bin/pialite-guard
    rm -f /usr/local/share/applications/pialite.desktop
    rm -f /usr/local/share/icons/hicolor/scalable/apps/pialite.svg
    rm -f /etc/xdg/autostart/pialite-tray.desktop
    rm -rf "$PREFIX"
    systemctl daemon-reload >/dev/null 2>&1 || true
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

# the old guard stops before its program is replaced - and if it won't
# stop, nothing is replaced (review G97-05)
if systemctl cat pialite-guard.service >/dev/null 2>&1; then
    if ! systemctl stop pialite-guard.service; then
        echo "The running PIA Lite guard could not be stopped - nothing was changed. Try again, or reboot first." >&2
        exit 1
    fi
fi
# the programs in use now are kept until the new ones are set up
had_old=0
if [ -x "$PREFIX/bin/pialite-guard" ]; then
    rm -rf "$PREFIX/bin.previous"
    cp -a "$PREFIX/bin" "$PREFIX/bin.previous"
    had_old=1
fi
install -d -m 0755 "$PREFIX" "$PREFIX/bin" "$PREFIX/share" "$PREFIX/share/pialite"
install -m 0755 "$HERE/bin/pialite-tray" "$HERE/bin/pialite-guard" "$PREFIX/bin/"
printf 'tarball\n' > "$PREFIX/share/pialite/install-kind"
install -d /usr/local/bin /usr/local/share/applications /usr/local/share/icons/hicolor/scalable/apps
ln -sf "$PREFIX/bin/pialite-tray" /usr/local/bin/pialite-tray
ln -sf "$PREFIX/bin/pialite-guard" /usr/local/bin/pialite-guard
sed "s|^Exec=.*|Exec=$PREFIX/bin/pialite-tray|" "$HERE/share/pialite.desktop" > /usr/local/share/applications/pialite.desktop
install -m 0644 "$HERE/share/pialite.svg" /usr/local/share/icons/hicolor/scalable/apps/pialite.svg

if [ "$1" = "--upgrade" ] && [ -f /var/lib/pialite/install.json ]; then
    set -- setup --kind tarball
else
    set -- setup --kind tarball --interactive
fi
if ! "$PREFIX/bin/pialite-guard" "$@"; then
    if [ "$had_old" = 1 ]; then
        # put the previous programs back and start the previous guard again
        rm -rf "$PREFIX/bin"
        mv "$PREFIX/bin.previous" "$PREFIX/bin"
        if systemctl start pialite-guard.service && systemctl is-active --quiet pialite-guard.service; then
            echo "Setting up this version FAILED (see above). The previous version was put back and its guard is running again." >&2
        else
            echo "Setting up this version FAILED (see above), and the previous guard could not be started again." >&2
            echo "If you are offline: sudo $PREFIX/bin/pialite-guard unlock" >&2
        fi
    else
        echo "Setting up PIA Lite FAILED (see above). To remove what was installed: sudo ./install.sh --uninstall" >&2
    fi
    exit 1
fi
rm -rf "$PREFIX/bin.previous"
echo
echo "Start the tray from your applications menu ('PIA Lite') or run: pialite-tray"
