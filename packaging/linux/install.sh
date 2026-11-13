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
# Only one of these runs at a time (a lock in /run/pialite-install/, a folder
# only root can enter): a second one stops before it looks at or changes
# anything (reviews R10-04, V11-05).
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

# Everything written so far is on disk - checked - before the next step (V11-01:
# a rename or a note that only sits in memory is lost in a power cut, and the
# next run would read the wrong story from what is left).
durable() {
    sync || { echo "Could not write $1 to disk - stopping here, before anything else changes." >&2; exit 1; }
}

same_file() { [ -f "$1" ] && [ -f "$2" ] && [ "$(sha256sum < "$1")" = "$(sha256sum < "$2")" ]; }
# the installed programs are exactly the ones in the copy $1
programs_match() {
    same_file "$1/bin/pialite-guard" "$PREFIX/bin/pialite-guard" && same_file "$1/bin/pialite-tray" "$PREFIX/bin/pialite-tray"
}

# Everything a restore needs is in the copy $1 - checked BEFORE the guard is
# stopped or a file removed, and when the copy is made (V11-02): both
# programs, the guard's earlier mode and DNS state, each settings file / menu
# entry / icon or the note that it wasn't there. A copy marked "complete 2"
# also has a manifest, and every file must still match it. Copies from older
# installers (no marker, or "1") have no manifest: their structure is checked.
valid_copy() {
    [ -d "$1/bin" ] && [ ! -L "$1/bin" ] || return 1
    for f in bin/pialite-guard bin/pialite-tray; do
        [ -f "$1/$f" ] && [ -x "$1/$f" ] || return 1
    done
    [ -f "$1/before-mode" ] && [ -f "$1/before-dns" ] || return 1
    case "$(cat "$1/before-mode")" in "" | off | startup | always) ;; *) return 1 ;; esac
    case "$(cat "$1/before-dns")" in true | false | off | unknown) ;; *) return 1 ;; esac
    for x in guard.json install.json menu icon; do
        [ -f "$1/$x" ] || [ -e "$1/absent-$x" ] || return 1
    done
    if [ "$(cat "$1/complete" 2>/dev/null)" = 2 ] && [ ! -f "$1/manifest" ]; then return 1; fi
    if [ -f "$1/manifest" ]; then
        (cd "$1" && sha256sum -c --quiet --strict manifest) >/dev/null 2>&1 || return 1
    fi
}

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
    return 1
}

# What watch_guard found, said plainly; $1 = what was done ("The previous
# version was put back" ...). 0 = protection confirmed - fully, or as far as
# the old guard reported it (PARTIALLY VERIFIED, R10-05).
protection() {
    if [ -n "$seen" ] && [ -n "$want_mode" ] && [ "$want_dns" != unknown ]; then
        case "$want_dns" in
            true) dns=", DNS only through the guard" ;;
            *) dns="" ;;
        esac
        echo "$1, and its guard protects as before (block mode $seen$dns)." >&2
        return 0
    elif [ -n "$seen" ] && [ -n "$want_mode" ]; then
        echo "$1 - PARTIALLY VERIFIED: its guard runs in block mode $seen with its block in place, the mode it had;" >&2
        echo "whether its DNS block was on before was NOT reported (an older version), so the DNS part is not verified." >&2
        return 0
    elif [ -n "$seen" ]; then
        echo "$1; its guard runs in block mode $seen with its block in place, but what it showed before couldn't be" >&2
        echo "read, so 'as before' isn't confirmed." >&2
    else
        echo "$1, but its protection could NOT be confirmed: $why." >&2
    fi
    return 1
}

kept_hint() {
    echo "Its copy is kept in $ROLL (try again: sudo ./install.sh --restore-previous)." >&2
    echo "If you are offline: sudo $PREFIX/bin/pialite-guard unlock" >&2
}

# After a failed `systemctl stop`: what systemd says about the guard; started
# again if it isn't running - and that start is checked; then watched (R10-03,
# V11-04). The outcome is for protection() to say: running and verified,
# running but not verified, or not started again ("remains STOPPED").
after_failed_stop() {
    state=$(systemctl show --property=ActiveState --value pialite-guard.service 2>/dev/null)
    if [ "$state" = active ]; then
        echo "The running PIA Lite guard could not be stopped (it is still running)." >&2
    else
        echo "Stopping the PIA Lite guard failed, and systemd now reports it as ${state:-unknown} - starting it again." >&2
        if ! systemctl start pialite-guard.service; then
            echo "It could NOT be started again: the guard remains STOPPED, so its protection is OFF." >&2
            seen=""
            why="the guard remains stopped"
            want_mode=$(cat "$ROLL/before-mode" 2>/dev/null)
            want_dns=$(cat "$ROLL/before-dns" 2>/dev/null)
            return 1
        fi
    fi
    watch_guard
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
        kept_hint
        return 1
    fi
    if protection "The previous version was put back"; then
        rm -rf /opt/pialite.rollback
        return 0
    fi
    kept_hint
    return 1
}

# Make sense of what an interrupted run left (R10-02, V11-01), before anything
# else. Sets $copy_note to "nothing-changed" when a complete copy was made but
# the installed programs are still exactly the ones in it. A copy is never
# dropped as harmless on a missing note alone.
settle_copies() {
    copy_note=""
    # complete, but its rename to $ROLL was lost (power cut): it IS the copy
    if [ -f "$PART/complete" ] && [ ! -e "$ROLL" ]; then
        echo "Found the copy of the previous version under its temporary name ($PART) - using it." >&2
        mv "$PART" "$ROLL"
        durable "the copy's name"
    fi
    if [ -e "$PART" ]; then
        if [ -e "$ROLL" ] || [ "$1" = upgrade ]; then
            # an unfinished copy can't restore anything; the guard is stopped only
            # after a copy is complete and on disk
            echo "Removing an unfinished copy an interrupted earlier upgrade left ($PART) - it can't be used." >&2
            rm -rf /opt/pialite.rollback.part
        fi
    fi
    if [ -e "$ROLL/complete" ] && [ ! -e "$ROLL/guard-stopped" ] && programs_match "$ROLL"; then
        copy_note=nothing-changed
    fi
}

case "$1" in
    --uninstall | --restore-previous | --upgrade | "") ;;
    *) echo "unknown option: $1 (use --upgrade, --uninstall or --restore-previous)" >&2; exit 1 ;;
esac

# One install / upgrade / uninstall / restore at a time, held until this
# script and everything it started have finished (R10-04). The lock file is
# in a folder only root can enter (V11-05): flock works on a read-only open,
# so a lock file any account can read is a lock any account can hold.
LOCKDIR=/run/pialite-install
LOCK=/run/pialite-install/lock
if ! command -v flock >/dev/null 2>&1; then
    echo "flock (util-linux) is needed so two installers can't run at once - nothing was changed." >&2
    exit 1
fi
case "$(stat -c '%u %a' /run 2>/dev/null)" in
    "0 755" | "0 700" | "0 711" | "0 750" | "0 751" | "0 1755") ;;
    *) echo "Note: /run isn't root's alone ($(stat -c '%U %a' /run 2>/dev/null)) - another account could get in the installer's way." >&2 ;;
esac
if [ -L "$LOCKDIR" ] || { [ -e "$LOCKDIR" ] && [ ! -d "$LOCKDIR" ]; } \
    || ! { [ -d "$LOCKDIR" ] || mkdir -m 0700 "$LOCKDIR" 2>/dev/null; } \
    || [ "$(stat -c %u "$LOCKDIR")" != 0 ] || ! chmod 0700 "$LOCKDIR" \
    || [ -L "$LOCK" ] || { [ -e "$LOCK" ] && [ ! -f "$LOCK" ]; } \
    || ! (umask 077; : >>"$LOCK") 2>/dev/null; then
    echo "Could not set up the installer lock $LOCK (it must be root's, in a folder only root can enter) - nothing was changed." >&2
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
        # Nothing is stopped or removed unless the copy has everything a restore
        # needs (R10-02, V11-02).
        settle_copies restore
        if [ ! -e "$ROLL" ] && [ -e "$PART" ]; then
            echo "The only copy ($PART) is unfinished: an upgrade was interrupted while saving it, before it" >&2
            echo "stopped the guard. It can't be used, and nothing was changed. Remove it:  sudo rm -rf $PART" >&2
            exit 1
        fi
        [ -e "$ROLL" ] || { echo "There is no kept previous version ($ROLL)." >&2; exit 1; }
        if ! valid_copy "$ROLL"; then
            echo "The kept copy ($ROLL) is incomplete or damaged - it is NOT used, and nothing was stopped or changed." >&2
            echo "Check PIA Lite (pialite-guard status); if it doesn't work, install it again from its .tar.gz." >&2
            exit 1
        fi
        rm -rf /opt/pialite.new # an interrupted run's staging: never the version in use
        if [ "$copy_note" = nothing-changed ]; then
            echo "That upgrade was interrupted before it stopped the guard, and the installed programs are still the ones" >&2
            echo "in the copy. Nothing to put back; the copy was removed." >&2
            rm -rf /opt/pialite.rollback
            exit 0
        fi
        if unit_exists && ! systemctl stop pialite-guard.service; then
            after_failed_stop || true
            protection "Nothing was put back" || true
            echo "The copy is still kept in $ROLL - run this again once the guard can be stopped (or reboot first)." >&2
            echo "If you are offline: sudo $PREFIX/bin/pialite-guard unlock" >&2
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
#    A complete copy is dropped only when the installed programs are still
#    the ones in it (V11-01).
settle_copies upgrade
if [ "$copy_note" = nothing-changed ]; then
    echo "Removing the copy an earlier upgrade made before it was interrupted ($ROLL) - the installed programs are" >&2
    echo "still the ones in it, so that run changed nothing." >&2
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
#    Made in $PART, with a manifest of every file; checked with the same test
#    a restore uses (V11-02); marked complete; on disk; renamed to $ROLL; and
#    the rename on disk too (R10-02, V11-01).
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
    (cd "$PART" && find . -type f ! -name manifest -exec sha256sum {} +) > "$PART/manifest"
    if ! valid_copy "$PART" || ! programs_match "$PART"; then
        echo "The copy of the version in use is incomplete - nothing was changed." >&2
        exit 1
    fi
    echo 2 > "$PART/complete" # 2 = has a manifest
    durable "the copy of the version in use"
    mv "$PART" "$ROLL"
    trap 'rm -rf /opt/pialite.new /opt/pialite.rollback' EXIT
    durable "the copy's name"
    had_old=1
fi

# 3. the old guard stops - and if it won't, nothing is replaced (G97-05). A
#    failed stop may still have stopped it: what systemd says decides, and the
#    guard is started again and checked like after a rollback (R10-03).
step="stopping the guard"
if [ "$had_old" = 1 ]; then
    : > "$ROLL/guard-stopped" # from here the guard may be stopped (--restore-previous needs to know)
    durable "the note that the guard is being stopped"
fi
if unit_exists && ! systemctl stop pialite-guard.service; then
    trap - EXIT
    set +e
    rm -rf /opt/pialite.new
    if [ "$had_old" = 1 ]; then
        after_failed_stop
        if protection "No program files were replaced"; then
            rm -rf /opt/pialite.rollback
        else
            kept_hint
            exit 1
        fi
    else
        echo "The guard could not be stopped - no program files were replaced." >&2
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
