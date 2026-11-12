# Sourced by the install.sh tests (reviews R98-01, N99-01, N99-07): they run
# ONLY in a fresh, private mount namespace where every place install.sh can
# touch on a real system is an empty tmpfs. Nothing a test does can reach a
# real installation, and it all vanishes when the test ends.
#
# The contract is checked, not assumed: every absolute path install.sh names
# must be inside a hidden folder (or the test refuses - add the folder here),
# the namespace must differ from the caller's, and no mount may be shared
# (a shared mount would carry the tmpfs layers back out).
# Needs root and unshare (util-linux). Can't isolate: refuse, never fall back.
HIDE="/opt /usr/local /var/lib /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system /etc/xdg/autostart"
INSTALL_SH="$HERE/../packaging/linux/install.sh"
refuse() { echo "refusing: $*"; exit 1; }

case "$HERE" in
    /opt/* | /usr/local/* | /var/lib/* | /etc/*) refuse "run the tests from a checkout outside the folders they hide" ;;
esac
[ "$(id -u)" = 0 ] || refuse "run as root (sudo) - the test needs its own mount namespace"
[ -f "$INSTALL_SH" ] || refuse "$INSTALL_SH not found"
for p in $(grep -oE '/(etc|usr|var|opt|lib|srv|home|root|boot|run|mnt|media)(/[A-Za-z0-9_.*-]+)*' "$INSTALL_SH" | sort -u); do
    covered=0
    for d in $HIDE; do
        case "$p" in "$d" | "$d"/*) covered=1 ;; esac
    done
    [ "$covered" = 1 ] || refuse "install.sh uses $p, which this test doesn't hide - add its folder to HIDE in tests/isolate.sh"
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
for d in $HIDE; do
    [ -d "$d" ] || continue # missing: install.sh only removes files there, and nothing is there to remove
    [ "$d" = /lib/systemd/system ] && [ -L /lib ] && continue # the same folder as /usr/lib/systemd/system
    [ -L "$d" ] && refuse "$d is a link - not hiding what it points at blindly"
    mount -t tmpfs -o size=64m,mode=0755 pialite-test "$d" || refuse "could not hide $d"
    grep -q "^pialite-test $d tmpfs " /proc/self/mounts || refuse "$d is not hidden"
done
[ -z "$(ls -A /opt)" ] && [ -z "$(ls -A /usr/local)" ] || refuse "/opt or /usr/local is not empty"
