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
# Only one of these runs at a time (a lock, /run/pialite-install.lock): a
# second one stops before it looks at or changes anything (review R10-04).
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
    rm -rf /opt/pialite /opt/pialite.new /opt/pialite.rollback /opt/pialite.rollback.part
    systemctl daemon-reload >/dev/null 2>&1 || true
    echo "PIA Lite removed."
}

DATA=/var/lib/pialite
NEW=/opt/pialite.new            # the new version, staged before anything in use changes
ROLL=/opt/pialite.rollback      # the version in use now - until the new one is set up, or kept for --restore-previous
PART=/opt/pialite.rollback.part # that copy while it is being made: renamed to $ROLL only once complete (R10-02)
MENU=/usr/local/share/applications/pialite.desktop
ICON=/usr/local/share/icons/hicolor/scalable/apps/pialite.svg

# fields of the guard's `status --json` (compact JSON, one line)
json_str() { printf '%s' "$2" | sed -n "s/.*\"$1\":\"\([a-z]*\)\".*/\1/p"; }
json_is() { printf '%s' "$3" | grep -q "\"$1\":$2"; } # json_is KEY true|false|null JSON
unit_exists() { systemctl cat pialite-guard.service >/dev/null 2>&1; }

# Wait for the guard to show the block mode, block and DNS block recorded in
# $ROLL (before-mode / before-dns). Sets $seen (its mode, when it does) or $why.
watch_guard() {
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
                return 0
            fi
        fi
        i=$((i + 1))
        sleep 1
    done
}

# What watch_guard found, said plainly; $1 = what was done ("The previous
# version was put back" ...). 0 = protection confirmed - fully, or as far as
# the old guard reported it (PARTIALLY VERIFIED, R10-05) - and $ROLL removed;
# otherwise $ROLL is kept.
verdict() {
    if [ -n "$seen" ] && [ -n "$want_mode" ] && [ "$want_dns" != unknown ]; then
        case "$want_dns" in
            true) dns=", DNS only through the guard" ;;
            *) dns="" ;;
        esac
        echo "$1, and its guard protects as before (block mode $seen$dns)." >&2
        rm -rf /opt/pialite.rollback
        return 0
    elif [ -n "$seen" ] && [ -n "$want_mode" ]; then
        echo "$1 - PARTIALLY VERIFIED: its guard runs in block mode $seen with its block in place, the mode it had;" >&2
        echo "whether its DNS block was on before was NOT reported (an older version), so the DNS part is not verified." >&2
        rm -rf /opt/pialite.rollback
        return 0
    elif [ -n "$seen" ]; then
        echo "$1; its guard runs in block mode $seen with its block in place, but what it showed before couldn't be" >&2
        echo "read, so 'as before' isn't confirmed." >&2
    else
        echo "$1, but its protection could NOT be confirmed: $why." >&2
    fi
    echo "Its copy is kept in $ROLL (try again: sudo ./install.sh --restore-previous)." >&2
    echo "If you are offline: sudo $PREFIX/bin/pialite-guard unlock" >&2
    return 1
}

# Put the copy in $ROLL back and start its guard. "As before" only when every
# file went back AND the guard itself shows the block mode, block and DNS
# block it had before (reviews R98-06, N99-02, N99-04). 0 = confirmed ($ROLL
# removed); otherwise $ROLL is kept and the reason printed.
restore_previous() {
    set +e
    bad=""
    rm -rf /opt/pialite/bin /opt/pialite/share || bad="$bad, removing the new programs"
    cp -a "$ROLL/bin" "$PREFIX/bin" || bad="$bad, the programs"
    if [ -d "$ROLL/share" ]; then cp -a "$ROLL/share" "$PREFIX/share" || bad="$bad, $PREFIX/share"; fi
    for f in guard.json install.json; do
        if [ -f "$ROLL/$f" ]; then
            cp -p "$ROLL/$f" "$DATA/$f" || bad="$bad, $DATA/$f"
        elif [ -e "$ROLL/absent-$f" ]; then
            rm -f "/var/lib/pialite/${f:?}" || bad="$bad, removing $DATA/$f" # it wasn't there before
        fi
    done
    if [ -f "$ROLL/menu" ]; then
        cp -p "$ROLL/menu" "$MENU" || bad="$bad, $MENU"
    elif [ -e "$ROLL/absent-menu" ]; then
        rm -f /usr/local/share/applications/pialite.desktop || bad="$bad, removing $MENU"
    fi
    if [ -f "$ROLL/icon" ]; then
        cp -p "$ROLL/icon" "$ICON" || bad="$bad, $ICON"
    elif [ -e "$ROLL/absent-icon" ]; then
        rm -f /usr/local/share/icons/hicolor/scalable/apps/pialite.svg || bad="$bad, removing $ICON"
    fi
    ln -sf "$PREFIX/bin/pialite-tray" /usr/local/bin/pialite-tray || bad="$bad, /usr/local/bin/pialite-tray"
    ln -sf "$PREFIX/bin/pialite-guard" /usr/local/bin/pialite-guard || bad="$bad, /usr/local/bin/pialite-guard"
    systemctl start pialite-guard.service || bad="$bad, starting the guard"
    watch_guard
    set -e
    if [ -n "$bad" ]; then
        echo "The previous version could NOT be put back completely - these failed:${bad#,}." >&2
        echo "Its copy is kept in $ROLL (try again: sudo ./install.sh --restore-previous)." >&2
        echo "If you are offline: sudo $PREFIX/bin/pialite-guard unlock" >&2
        return 1
    fi
    verdict "The previous version was put back"
}

# A copy is complete when it says so (written last, R10-02) - or, for a copy
# an older installer made, when its last file (before-dns) has its content.
complete_copy() { [ -x "$1/bin/pialite-guard" ] && { [ -e "$1/complete" ] || [ -s "$1/before-dns" ]; }; }

case "$1" in
    --uninstall | --restore-previous | --upgrade | "") ;;
    *) echo "unknown option: $1 (use --upgrade, --uninstall or --restore-previous)" >&2; exit 1 ;;
esac

# One install / upgrade / uninstall / restore at a time, held until this
# script and everything it started have finished (R10-04). In /run, where only
# root can create files, so no other account can hold or plant the lock.
LOCK=/run/pialite-install.lock
if ! command -v flock >/dev/null 2>&1; then
    echo "flock (util-linux) is needed so two installers can't run at once - nothing was changed." >&2
    exit 1
fi
# (a failed `exec` redirection ends a POSIX shell at once - so try it in a subshell first)
if [ -L "$LOCK" ] || ! (: >>"$LOCK") 2>/dev/null; then
    echo "Could not open the installer lock $LOCK - nothing was changed." >&2
    exit 1
fi
exec 9>>"$LOCK"
if ! flock -n 9; then
    echo "Another PIA Lite install, upgrade, uninstall or restore is running - nothing was changed." >&2
    echo "Wait for it to finish, then run this again." >&2
    exit 1
fi

case "$1" in
    --uninstall) uninstall; exit 0 ;;
    --restore-previous)
        # put back the copy an unconfirmed rollback (or a power cut) left (N99-03).
        # An incomplete copy is never used, and the guard isn't stopped for it (R10-02).
        if [ ! -e "$ROLL" ] && [ -e "$PART" ]; then
            echo "The only copy ($PART) is incomplete: an upgrade was interrupted while saving it, before it" >&2
            echo "stopped the guard or replaced anything - the installed version is the one in use. Nothing was" >&2
            echo "changed. Remove that copy:  sudo rm -rf $PART" >&2
            exit 1
        fi
        [ -e "$ROLL" ] || { echo "There is no kept previous version ($ROLL)." >&2; exit 1; }
        if ! complete_copy "$ROLL"; then
            echo "The kept copy ($ROLL) is incomplete - it is NOT used, and nothing was changed." >&2
            echo "Check PIA Lite (pialite-guard status); if it doesn't work, install it again from its .tar.gz." >&2
            exit 1
        fi
        rm -rf /opt/pialite.new # an interrupted run's staging: never the version in use
        if [ -e "$ROLL/complete" ] && [ ! -e "$ROLL/guard-stopped" ]; then
            echo "That upgrade was interrupted before it stopped the guard or replaced anything - the installed version" >&2
            echo "is the one in the copy. Nothing to put back; the copy was removed." >&2
            rm -rf /opt/pialite.rollback
            exit 0
        fi
        if unit_exists && ! systemctl stop pialite-guard.service; then
            state=$(systemctl show --property=ActiveState --value pialite-guard.service 2>/dev/null || true)
            if [ "$state" != active ]; then
                systemctl start pialite-guard.service || true # a failed stop may still have stopped it (R10-03)
            fi
            echo "The running guard could not be stopped cleanly (systemd reported it as ${state:-unknown}; started again if" >&2
            echo "it wasn't running) - no program files were replaced. What it protects now: pialite-guard status" >&2
            exit 1
        fi
        restore_previous && exit 0
        exit 1 ;;
esac

if ! command -v systemctl >/dev/null 2>&1; then
    echo "PIA Lite's guard needs systemd. You can still run the tray alone: ./bin/pialite-tray" >&2
    exit 1
fi

# 0. nothing is changed while an earlier recovery is unfinished, or when the
#    installed guard isn't one this installer can put back (N99-03, N99-06).
#    A copy an interrupted run left BEFORE it stopped the guard is of no use:
#    that run changed nothing (the guard is stopped only after the copy is
#    complete and marked) - it is removed (R10-02).
if [ -e "$PART" ]; then
    echo "Removing an incomplete copy an interrupted earlier upgrade left ($PART) - that run changed nothing." >&2
    rm -rf /opt/pialite.rollback.part
fi
if [ -e "$ROLL/complete" ] && [ ! -e "$ROLL/guard-stopped" ]; then
    echo "Removing the copy an earlier upgrade made before it was interrupted ($ROLL) - it stopped and changed nothing." >&2
    rm -rf /opt/pialite.rollback
fi
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
rm -rf /opt/pialite.new
trap 'rm -rf /opt/pialite.new' EXIT
install -d -m 0755 "$NEW/bin" "$NEW/share/pialite"
install -m 0755 "$HERE/bin/pialite-tray" "$HERE/bin/pialite-guard" "$NEW/bin/"
printf 'tarball\n' > "$NEW/share/pialite/install-kind"
sed "s|^Exec=.*|Exec=$PREFIX/bin/pialite-tray|" "$HERE/share/pialite.desktop" > "$NEW/pialite.desktop"
install -m 0644 "$HERE/share/pialite.svg" "$NEW/pialite.svg"

# 2. a copy of what is in use now - programs, settings, menu entry, and what
#    the guard says about its protection - to put back if anything after the
#    stop fails (also after a power cut: sudo ./install.sh --restore-previous).
#    Made in $PART; only when every part is there is it marked complete,
#    written to disk and renamed to $ROLL (R10-02).
had_old=0
if [ -x "$PREFIX/bin/pialite-guard" ]; then
    step="saving the version in use"
    mkdir -m 0700 "$PART"
    trap 'rm -rf /opt/pialite.new /opt/pialite.rollback.part' EXIT
    cp -a "$PREFIX/bin" "$PART/bin"
    if [ -d "$PREFIX/share" ]; then cp -a "$PREFIX/share" "$PART/share"; fi
    for f in guard.json install.json; do
        if [ -f "$DATA/$f" ]; then cp -p "$DATA/$f" "$PART/$f"; else : > "$PART/absent-$f"; fi
    done
    if [ -f "$MENU" ]; then cp -p "$MENU" "$PART/menu"; else : > "$PART/absent-menu"; fi
    if [ -f "$ICON" ]; then cp -p "$ICON" "$PART/icon"; else : > "$PART/absent-icon"; fi
    before=$("$PREFIX/bin/pialite-guard" status --json 2>/dev/null || true)
    json_str mode "$before" > "$PART/before-mode"
    if json_is dns_only_guard true "$before"; then echo true
    elif json_is dns_only_guard false "$before"; then echo false
    elif json_is dns_only_guard null "$before"; then echo off
    else echo unknown
    fi > "$PART/before-dns"
    # every part is there before the copy counts as complete
    for f in bin/pialite-guard bin/pialite-tray before-mode before-dns; do
        [ -e "$PART/$f" ] || { echo "The copy of the version in use is missing $f - nothing was changed." >&2; exit 1; }
    done
    for x in guard.json install.json menu icon; do
        [ -e "$PART/$x" ] || [ -e "$PART/absent-$x" ] || { echo "The copy of the version in use is missing $x - nothing was changed." >&2; exit 1; }
    done
    [ -s "$PART/before-dns" ] || { echo "The copy of the version in use is incomplete - nothing was changed." >&2; exit 1; }
    echo 1 > "$PART/complete"
    sync # on disk before it counts: a power cut can't leave a "complete" copy with missing contents
    mv "$PART" "$ROLL"
    trap 'rm -rf /opt/pialite.new /opt/pialite.rollback' EXIT
    had_old=1
fi

# 3. the old guard stops - and if it won't, nothing is replaced (G97-05). A
#    failed stop may still have stopped it: what systemd says decides, and the
#    guard is started again and checked like after a rollback (R10-03).
step="stopping the guard"
if [ "$had_old" = 1 ]; then
    : > "$ROLL/guard-stopped" # from here the guard may be stopped (--restore-previous needs to know)
fi
if unit_exists && ! systemctl stop pialite-guard.service; then
    trap - EXIT
    set +e
    rm -rf /opt/pialite.new
    state=$(systemctl show --property=ActiveState --value pialite-guard.service 2>/dev/null)
    case "$state" in
        active) echo "The running PIA Lite guard could not be stopped (it is still running)." >&2 ;;
        *)
            echo "Stopping the PIA Lite guard failed, and systemd now reports it as ${state:-unknown} - starting it again." >&2
            systemctl start pialite-guard.service || echo "It could not be started again." >&2 ;;
    esac
    if [ "$had_old" = 1 ]; then
        watch_guard
        verdict "No program files were replaced" || exit 1
    else
        echo "No program files were replaced." >&2
    fi
    echo "Try again, or reboot first." >&2
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
    rm -rf /opt/pialite.new
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
rm -rf /opt/pialite/bin /opt/pialite/share
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
rm -rf /opt/pialite.new /opt/pialite.rollback
echo
echo "Start the tray from your applications menu ('PIA Lite') or run: pialite-tray"
