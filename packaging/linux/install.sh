#!/bin/sh
# PIA Lite installer for the .tar.gz (any Linux distribution with systemd).
#
#   sudo ./install.sh              install - asks which features you want
#   sudo ./install.sh --upgrade    install this version, keep your features
#   sudo ./install.sh --uninstall  remove PIA Lite (block rules, service, files)
#   sudo ./install.sh --restore-previous
#                                  put back the version an unfinished upgrade kept
#                                  (after a failure it couldn't confirm, or a power cut)
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
    rm -rf /opt/pialite /opt/pialite.new /opt/pialite.rollback
    systemctl daemon-reload >/dev/null 2>&1 || true
    echo "PIA Lite removed."
}

DATA=/var/lib/pialite
NEW=/opt/pialite.new       # the new version, staged before anything in use changes
ROLL=/opt/pialite.rollback # the version in use now - until the new one is set up, or kept for --restore-previous
MENU=/usr/local/share/applications/pialite.desktop
ICON=/usr/local/share/icons/hicolor/scalable/apps/pialite.svg

# fields of the guard's `status --json` (compact JSON, one line)
json_str() { printf '%s' "$2" | sed -n "s/.*\"$1\":\"\([a-z]*\)\".*/\1/p"; }
json_is() { printf '%s' "$3" | grep -q "\"$1\":$2"; } # json_is KEY true|false|null JSON
unit_exists() { systemctl cat pialite-guard.service >/dev/null 2>&1; }

# Put the copy in $ROLL back and start its guard. "As before" only when every
# file went back AND the guard itself shows the block mode, block and DNS
# block it had before (reviews R98-06, N99-02, N99-04). 0 = confirmed ($ROLL
# removed); otherwise $ROLL is kept and the reason printed.
restore_previous() {
    set +e
    bad=""
    rm -rf "${PREFIX:?}/bin" "${PREFIX:?}/share" || bad="$bad, removing the new programs"
    cp -a "$ROLL/bin" "$PREFIX/bin" || bad="$bad, the programs"
    if [ -d "$ROLL/share" ]; then cp -a "$ROLL/share" "$PREFIX/share" || bad="$bad, $PREFIX/share"; fi
    for f in guard.json install.json; do
        if [ -f "$ROLL/$f" ]; then
            cp -p "$ROLL/$f" "$DATA/$f" || bad="$bad, $DATA/$f"
        elif [ -e "$ROLL/absent-$f" ]; then
            rm -f "$DATA/$f" || bad="$bad, removing $DATA/$f" # it wasn't there before
        fi
    done
    for x in "menu $MENU" "icon $ICON"; do
        name=${x%% *}
        path=${x#* }
        if [ -f "$ROLL/$name" ]; then
            cp -p "$ROLL/$name" "$path" || bad="$bad, $path"
        elif [ -e "$ROLL/absent-$name" ]; then
            rm -f "$path" || bad="$bad, removing $path"
        fi
    done
    ln -sf "$PREFIX/bin/pialite-tray" /usr/local/bin/pialite-tray || bad="$bad, /usr/local/bin/pialite-tray"
    ln -sf "$PREFIX/bin/pialite-guard" /usr/local/bin/pialite-guard || bad="$bad, /usr/local/bin/pialite-guard"
    systemctl start pialite-guard.service || bad="$bad, starting the guard"
    want_mode=$(cat "$ROLL/before-mode" 2>/dev/null)
    want_dns=$(cat "$ROLL/before-dns" 2>/dev/null)
    why="it did not answer"
    seen=""
    i=0
    while [ $i -lt "${PIALITE_ROLLBACK_WAIT:-30}" ]; do
        now=$("$PREFIX/bin/pialite-guard" status --json 2>/dev/null)
        mode=$(json_str mode "$now")
        if [ -n "$mode" ]; then
            if [ -n "$want_mode" ] && [ "$mode" != "$want_mode" ]; then
                why="it runs in block mode $mode instead of $want_mode"
            elif [ "$mode" != off ] && ! json_is armed true "$now"; then
                why="its block ($mode) is not in place"
            elif [ "$want_dns" = true ] && ! json_is dns_only_guard true "$now"; then
                why="its DNS block / redirect is not on again (it was before)"
            elif [ -z "$want_mode" ] && [ "$mode" = off ]; then
                why="it runs in block mode off, and what it protected before couldn't be read"
            else
                seen=$mode
                break
            fi
        fi
        i=$((i + 1))
        sleep 1
    done
    set -e
    if [ -n "$bad" ]; then
        echo "The previous version could NOT be put back completely - these failed:${bad#,}." >&2
    elif [ -n "$seen" ] && [ -n "$want_mode" ]; then
        case "$want_dns" in
            true) dns=", DNS only through the guard" ;;
            unknown) dns="; its DNS block wasn't reported before, so that part isn't checked" ;;
            *) dns="" ;;
        esac
        echo "The previous version was put back, and its guard protects as before (block mode $seen$dns)." >&2
        rm -rf "${ROLL:?}"
        return 0
    elif [ -n "$seen" ]; then
        echo "The previous version was put back; its guard runs in block mode $seen with its block in place, but what" >&2
        echo "it showed before couldn't be read, so 'as before' isn't confirmed." >&2
    else
        echo "The previous version was put back, but its protection could NOT be confirmed: $why." >&2
    fi
    echo "Its copy is kept in $ROLL (try again: sudo ./install.sh --restore-previous)." >&2
    echo "If you are offline: sudo $PREFIX/bin/pialite-guard unlock" >&2
    return 1
}

case "$1" in
    --uninstall) uninstall; exit 0 ;;
    --restore-previous)
        # put back the copy an unconfirmed rollback (or a power cut) left (review N99-03)
        [ -d "$ROLL/bin" ] || { echo "There is no kept previous version ($ROLL)." >&2; exit 1; }
        if unit_exists && ! systemctl stop pialite-guard.service; then
            echo "The running guard could not be stopped - nothing was changed." >&2
            exit 1
        fi
        restore_previous && exit 0
        exit 1 ;;
    --upgrade|"") ;;
    *) echo "unknown option: $1 (use --upgrade, --uninstall or --restore-previous)" >&2; exit 1 ;;
esac

if ! command -v systemctl >/dev/null 2>&1; then
    echo "PIA Lite's guard needs systemd. You can still run the tray alone: ./bin/pialite-tray" >&2
    exit 1
fi

# 0. nothing is changed while an earlier recovery is unfinished, or when the
#    installed guard isn't one this installer can put back (N99-03, N99-06)
if [ -e "$ROLL" ]; then
    echo "An earlier upgrade couldn't confirm it put the previous version back; that copy is kept in $ROLL." >&2
    echo "Nothing was changed. Put it back:  sudo ./install.sh --restore-previous" >&2
    echo "Or, if PIA Lite works as it is (pialite-guard status), remove the copy and run this again:  sudo rm -rf $ROLL" >&2
    exit 1
fi
if unit_exists && [ ! -x "$PREFIX/bin/pialite-guard" ]; then
    echo "A PIA Lite guard service is set up, but its program isn't $PREFIX/bin/pialite-guard - this isn't an" >&2
    echo "installation this script can upgrade and put back. Nothing was changed. Remove it first" >&2
    echo "(sudo pialite-guard teardown, or your package manager), then run this again." >&2
    exit 1
fi

# 1. stage the new version next to the old one - nothing in use is touched,
#    and a failure here (disk full...) changes nothing (review R98-02)
step="copying the new files"
rm -rf "${NEW:?}"
trap 'rm -rf "${NEW:?}"' EXIT
install -d -m 0755 "$NEW/bin" "$NEW/share/pialite"
install -m 0755 "$HERE/bin/pialite-tray" "$HERE/bin/pialite-guard" "$NEW/bin/"
printf 'tarball\n' > "$NEW/share/pialite/install-kind"
sed "s|^Exec=.*|Exec=$PREFIX/bin/pialite-tray|" "$HERE/share/pialite.desktop" > "$NEW/pialite.desktop"
install -m 0644 "$HERE/share/pialite.svg" "$NEW/pialite.svg"

# 2. a copy of what is in use now - programs, settings, menu entry, and what
#    the guard says about its protection - to put back if anything after the
#    stop fails (also after a power cut: sudo ./install.sh --restore-previous)
had_old=0
if [ -x "$PREFIX/bin/pialite-guard" ]; then
    step="saving the version in use"
    mkdir -m 0700 "$ROLL"
    trap 'rm -rf "${NEW:?}" "${ROLL:?}"' EXIT
    cp -a "$PREFIX/bin" "$ROLL/bin"
    if [ -d "$PREFIX/share" ]; then cp -a "$PREFIX/share" "$ROLL/share"; fi
    for f in guard.json install.json; do
        if [ -f "$DATA/$f" ]; then cp -p "$DATA/$f" "$ROLL/$f"; else : > "$ROLL/absent-$f"; fi
    done
    for x in "menu $MENU" "icon $ICON"; do
        if [ -f "${x#* }" ]; then cp -p "${x#* }" "$ROLL/${x%% *}"; else : > "$ROLL/absent-${x%% *}"; fi
    done
    before=$("$PREFIX/bin/pialite-guard" status --json 2>/dev/null || true)
    json_str mode "$before" > "$ROLL/before-mode"
    if json_is dns_only_guard true "$before"; then echo true
    elif json_is dns_only_guard false "$before"; then echo false
    elif json_is dns_only_guard null "$before"; then echo off
    else echo unknown
    fi > "$ROLL/before-dns"
    had_old=1
fi

# 3. the old guard stops - and if it won't, nothing is replaced (G97-05)
step="stopping the guard"
if unit_exists && ! systemctl stop pialite-guard.service; then
    echo "The running PIA Lite guard could not be stopped - nothing was changed. Try again, or reboot first." >&2
    exit 1
fi

# 4. from here ANY failure (or Ctrl+C) puts the previous version back
finished=0
rollback() {
    [ "$finished" = 1 ] && return 0
    finished=1
    trap - EXIT INT TERM
    set +e
    echo "Installing this version FAILED while $step (see above)." >&2
    rm -rf "${NEW:?}"
    if [ "$had_old" != 1 ]; then
        echo "There was no previous version to go back to. To remove what was installed: sudo ./install.sh --uninstall" >&2
        exit 1
    fi
    restore_previous
    exit 1
}
trap rollback EXIT
trap 'rollback' INT TERM

step="putting the new programs in place"
rm -rf "${PREFIX:?}/bin" "${PREFIX:?}/share"
install -d -m 0755 "$PREFIX"
mv "$NEW/bin" "$PREFIX/bin"
mv "$NEW/share" "$PREFIX/share"
step="adding the menu entry and commands"
install -d /usr/local/bin /usr/local/share/applications /usr/local/share/icons/hicolor/scalable/apps
ln -sf "$PREFIX/bin/pialite-tray" /usr/local/bin/pialite-tray
ln -sf "$PREFIX/bin/pialite-guard" /usr/local/bin/pialite-guard
install -m 0644 "$NEW/pialite.desktop" "$MENU"
install -m 0644 "$NEW/pialite.svg" "$ICON"

step="setting up"
if [ "$1" = "--upgrade" ] && [ -f "$DATA/install.json" ]; then
    "$PREFIX/bin/pialite-guard" setup --kind tarball
else
    "$PREFIX/bin/pialite-guard" setup --kind tarball --interactive
fi

finished=1
trap - EXIT INT TERM
rm -rf "${NEW:?}" "${ROLL:?}"
echo
echo "Start the tray from your applications menu ('PIA Lite') or run: pialite-tray"
