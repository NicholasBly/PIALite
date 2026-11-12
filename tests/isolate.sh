# Sourced by the install.sh tests (review R98-01): they run ONLY in a private
# mount namespace where every place a real PIA Lite lives - /opt, /usr/local,
# /var/lib, the systemd unit folders - is an empty tmpfs. Nothing a test does
# there can reach a real installation, and it all vanishes when the test ends.
# Not isolated yet? Start the calling script again in its own namespace.
# Needs: root, unshare (util-linux). Without them: refuse, never fall back.
case "$HERE" in
    /opt/* | /usr/local/* | /var/lib/*) echo "refusing: run the tests from a checkout outside /opt, /usr/local and /var/lib"; exit 1 ;;
esac
if [ "$(id -u)" != 0 ]; then echo "refusing: run as root (sudo) - the test needs its own mount namespace"; exit 1; fi
# Isolated = our mount namespace differs from the one of the program that
# started us (unshare execs this script, so that is the shell that ran the
# test). Can't tell = refuse; never mount anything in a shared namespace.
me=$(readlink /proc/self/ns/mnt 2>/dev/null)
parent=$(readlink "/proc/$PPID/ns/mnt" 2>/dev/null)
if [ -z "$me" ] || [ -z "$parent" ]; then echo "refusing: can't tell whether this test is isolated"; exit 1; fi
if [ "$me" = "$parent" ]; then
    command -v unshare >/dev/null 2>&1 || { echo "refusing: unshare is needed to keep this test away from real files"; exit 1; }
    exec unshare --mount --propagation private sh "$0" "$@"
fi
# here: our own mount namespace
for d in /opt /usr/local /var/lib /etc/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
    [ -d "$d" ] || continue
    [ "$d" = /lib/systemd/system ] && [ -L /lib ] && continue # the same folder as /usr/lib/...
    mount -t tmpfs -o size=64m,mode=0755 pialite-test "$d" || { echo "refusing: could not hide $d"; exit 1; }
    grep -q "^pialite-test $d tmpfs " /proc/self/mounts || { echo "refusing: $d is not hidden"; exit 1; }
done
[ -z "$(ls -A /opt)" ] && [ -z "$(ls -A /usr/local)" ] || { echo "refusing: /opt or /usr/local is not empty"; exit 1; }
