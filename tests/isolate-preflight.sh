#!/bin/sh
# Review R10-01: the install.sh tests refuse to run - before creating
# anything - where a folder they write under is missing or reached through a
# link. Checked in throwaway root filesystems (an empty tmpfs plus READ-ONLY
# bind mounts of this system), one case at a time - never by removing
# folders from a real system. Nothing here can write to this system: every
# folder taken from it is read-only, and the rest is a tmpfs that vanishes.
# Run as root: sudo sh tests/isolate-preflight.sh
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$(id -u)" = 0 ] || { echo "refusing: run as root"; exit 1; }
command -v unshare >/dev/null 2>&1 && command -v chroot >/dev/null 2>&1 || { echo "refusing: needs unshare and chroot"; exit 1; }
# a private mount namespace of our own: every mount below vanishes with it
if [ "${PIALITE_PREFLIGHT_NS:-}" != 1 ]; then
    exec env PIALITE_PREFLIGHT_NS=1 unshare --mount --propagation private sh "$0" "$@"
fi
if grep -q ' shared:' /proc/self/mountinfo; then echo "refusing: mounts are shared"; exit 1; fi
case "$HERE" in /home/*) ;; *) echo "refusing: needs the checkout under /home (it is bound read-only into the test roots)"; exit 1 ;; esac
fails=0
OUT=$(mktemp)

ro_bind() { # SRC DST: the same folder, read-only (a link is copied as a link)
    if [ -L "$1" ]; then ln -s "$(readlink "$1")" "$2"; return; fi
    [ -d "$1" ] || return 0
    mkdir -p "$2"
    mount -n --bind "$1" "$2" && mount -n -o remount,bind,ro "$2" || { echo "refusing: could not bind $1 read-only"; exit 1; }
}
# root_without MISSING: a root with this system's folders read-only, except
# MISSING (/opt, /usr/local, /var/lib or /run), which doesn't exist in it
root_without() {
    R=$(mktemp -d)
    mount -n -t tmpfs -o size=16m,mode=0755 preflight "$R"
    for e in /*; do
        n=${e#/}
        case "$n" in proc | sys | dev | tmp | run | usr | var) continue ;; esac
        [ "$e" = "$1" ] && continue
        ro_bind "$e" "$R/$n"
    done
    for top in usr var; do
        if [ "$1" = "/$top/local" ] || [ "$1" = "/$top/lib" ]; then
            mkdir "$R/$top" # everything in it but the missing one
            for e in /"$top"/*; do [ "$e" = "$1" ] || ro_bind "$e" "$R/$top/${e##*/}"; done
        else
            ro_bind "/$top" "$R/$top"
        fi
    done
    [ "$1" = /run ] || mkdir "$R/run"
    mkdir -m 1777 "$R/tmp"
    mkdir "$R/proc" && mount -n -t proc proc "$R/proc"
    ro_bind /dev "$R/dev"
}
case_() { # name, folder that must not appear, expected text, test script
    chroot "$R" sh "$HERE/$4" > "$OUT" 2>&1; rc=$?
    if [ "$rc" != 0 ] && grep -q "$3" "$OUT" && { [ -z "$2" ] || { [ ! -e "$R$2" ] && [ ! -L "$R$2" ]; }; }; then
        echo "PASS: $1"
    else
        echo "FAIL: $1 (exit $rc)"; sed 's/^/    | /' "$OUT"; fails=$((fails + 1))
    fi
}

# each folder the tests write under, missing: refused, and still missing
for d in /opt /usr/local /var/lib /run; do
    root_without "$d"
    for t in install-sh-upgrade.sh install-sh-uninstall.sh; do
        case_ "$t refuses when $d is missing, and doesn't create it" "$d" "refusing: $d doesn't exist here" "$t"
    done
done
# /opt reached through a link: refused
root_without /opt
mkdir "$R/srv-opt" && ln -s srv-opt "$R/opt"
case_ "refuses when /opt is a link" "" "refusing: /opt is reached through a link" install-sh-uninstall.sh
[ -z "$(ls -A "$R/srv-opt")" ] || { echo "FAIL: something was written where the /opt link points"; fails=$((fails + 1)); }

# positive control: in a root that has everything, the test runs and passes
root_without none
chroot "$R" sh "$HERE/install-sh-uninstall.sh" > "$OUT" 2>&1; rc=$?
if [ "$rc" = 0 ] && grep -q "all install.sh uninstall checks passed" "$OUT"; then
    echo "PASS: with every folder there, the test runs (positive control)"
else
    echo "FAIL: positive control (exit $rc)"; sed 's/^/    | /' "$OUT"; fails=$((fails + 1))
fi

rm -f "$OUT"
[ "$fails" = 0 ] && echo "all isolation preflight checks passed"
exit "$fails"
