# Sourced by the install.sh tests (reviews R98-01, N99-01, N99-07, R10-01):
# they run ONLY in a fresh, private mount namespace where every place
# install.sh or the tests can touch on a real system is an empty tmpfs.
# Nothing a test does can reach a real installation, and it all vanishes when
# the test ends.
#
# The contract is checked, not assumed:
#  * WRITE folders - install.sh or the tests create files under them - must
#    exist, be reached without a link, and be hidden. A missing one is
#    refused BEFORE anything runs: the test would otherwise create it on the
#    real system (R10-01).
#  * REMOVE-ONLY folders - install.sh only looks for and deletes files there -
#    are hidden when they exist; when one doesn't, the test checks at the end
#    that it still doesn't (still_isolated).
#  * every absolute path install.sh names must be inside one of them (or be
#    /bin/sh or /dev/null), and every path the calling test names inside a
#    WRITE folder (or /bin, /usr/bin) - else refuse and name the folder to add.
#  * the namespace must differ from the caller's and no mount may be shared
#    (a shared mount would carry the tmpfs layers back out).
# Needs root and unshare (util-linux). Can't isolate: refuse, never fall back.
WRITE="/opt /usr/local /var/lib /run"
REMOVE_ONLY="/etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /etc/xdg/autostart"
INSTALL_READ="/bin/sh /dev/null" # install.sh's interpreter and null device
READ_ONLY="/bin /usr/bin /dev/null"  # system programs the tests run
INSTALL_SH="$HERE/../packaging/linux/install.sh"
refuse() { echo "refusing: $*"; exit 1; }
inside() { # inside PATH FOLDER... : 0 when PATH is one of the folders or under one
    p=$1; shift
    for d in "$@"; do case "$p" in "$d" | "$d"/*) return 0 ;; esac; done
    return 1
}
# absolute paths a script names (not ones that only end a variable, like "$WORK/bin")
paths_in() { grep -oE '(^|[^A-Za-z0-9_}).$-])/(etc|usr|var|opt|lib|srv|home|root|boot|run|mnt|media|bin|proc|dev|sbin)(/[A-Za-z0-9_.*-]+)*' "$1" | sed 's|^[^/]*||' | sort -u; }

case "$HERE" in
    /opt/* | /usr/local/* | /var/lib/* | /run/* | /etc/*) refuse "run the tests from a checkout outside the folders they hide" ;;
esac
[ "$(id -u)" = 0 ] || refuse "run as root (sudo) - the test needs its own mount namespace"
[ -f "$INSTALL_SH" ] || refuse "$INSTALL_SH not found"
# shellcheck disable=SC2086 # the folder lists are meant to split
for p in $(paths_in "$INSTALL_SH"); do
    inside "$p" $WRITE $REMOVE_ONLY $INSTALL_READ || refuse "install.sh uses $p, which this test doesn't hide - add its folder to WRITE or REMOVE_ONLY in tests/isolate.sh"
done
# shellcheck disable=SC2086
for p in $(paths_in "$0"); do
    inside "$p" $WRITE $READ_ONLY || refuse "$0 uses $p, which isn't in a folder this test hides - add it to WRITE in tests/isolate.sh"
done
# a WRITE folder that is missing, or reached through a link, is refused before
# anything else happens (a link on the way: the hiding would be checked at a
# different place than the one written to)
for d in $WRITE; do
    [ -d "$d" ] || refuse "$d doesn't exist here - the test would create it on this system. Run it where $d exists (a VM or container)."
    [ "$(readlink -f "$d")" = "$d" ] || refuse "$d is reached through a link ($(readlink -f "$d")) - not hiding what it points at blindly"
done

# Isolated = our own mount namespace (it differs from the program that started
# us: unshare execs this script) AND every mount in it private.
me=$(readlink /proc/self/ns/mnt 2>/dev/null)
parent=$(readlink "/proc/$PPID/ns/mnt" 2>/dev/null)
[ -n "$me" ] && [ -n "$parent" ] || refuse "can't tell whether this test is isolated"
if [ "$me" = "$parent" ] || grep -q ' shared:' /proc/self/mountinfo; then
    tries=${PIALITE_ISOLATE_TRIES:-0}
    [ "$tries" = 0 ] || refuse "could not get a private mount namespace"
    command -v unshare >/dev/null 2>&1 || refuse "unshare is needed to keep this test away from real files"
    exec env PIALITE_ISOLATE_TRIES=1 unshare --mount --propagation private sh "$0" "$@"
fi

# here: a private namespace of our own
hide() { # -n: mount itself writes nothing (it would put /run/mount/utab into the hidden /run)
    mount -n -t tmpfs -o size=64m,mode=0755 pialite-test "$1" || refuse "could not hide $1"
    grep -q "^pialite-test $1 tmpfs " /proc/self/mounts || refuse "$1 is not hidden"
}
for d in $WRITE; do hide "$d"; done
ABSENT=""
for d in $REMOVE_ONLY; do
    if [ "$d" = /lib/systemd/system ] && [ -L /lib ]; then continue; fi # the same folder as /usr/lib/systemd/system
    if [ ! -e "$d" ] && [ ! -L "$d" ]; then
        ABSENT="$ABSENT $d" # install.sh only removes files there; checked again at the end
        continue
    fi
    [ -L "$d" ] && refuse "$d is a link - not hiding what it points at blindly"
    [ "$(readlink -f "$d")" = "$d" ] || refuse "$d is reached through a link - not hiding what it points at blindly"
    hide "$d"
done
# every WRITE folder is now an empty tmpfs of this test's own
for d in $WRITE; do
    [ -z "$(ls -A "$d")" ] || refuse "$d is not empty after hiding it"
done

# For the test's last check: a remove-only folder that didn't exist still
# doesn't (it would be on the real system - nothing hides it).
still_isolated() {
    for d in $ABSENT; do
        if [ -e "$d" ] || [ -L "$d" ]; then
            echo "    $d was created - it is NOT hidden (add it to WRITE in tests/isolate.sh)"
            return 1
        fi
    done
    for d in $WRITE; do
        grep -q "^pialite-test $d tmpfs " /proc/self/mounts || { echo "    $d is no longer hidden"; return 1; }
    done
}
