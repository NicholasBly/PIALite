#!/bin/sh
# install.sh --upgrade (review G97-05): a guard that won't stop means nothing
# is replaced; a failed setup puts the previous programs back and starts the
# previous guard. Fake systemctl and fake programs; run as root on a machine
# WITHOUT PIA Lite (it writes /opt/pialite and /usr/local/{bin,share} and
# removes them again).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d)
cleanup() {
    rm -rf "$WORK" /opt/pialite /usr/local/bin/pialite-tray /usr/local/bin/pialite-guard \
        /usr/local/share/applications/pialite.desktop /usr/local/share/icons/hicolor/scalable/apps/pialite.svg
}
trap cleanup EXIT
if [ -e /opt/pialite ]; then echo "refusing: /opt/pialite exists (PIA Lite installed?)"; exit 1; fi
fails=0
check() { # name, condition...
    name=$1; shift
    if "$@"; then echo "PASS: $name"; else echo "FAIL: $name"; fails=$((fails + 1)); fi
}
# a "new version" tarball: its guard's setup succeeds or fails on demand
mkdir -p "$WORK/pkg/bin" "$WORK/pkg/share" "$WORK/fake"
cp "$HERE/../packaging/linux/install.sh" "$WORK/pkg/"
printf '[Desktop Entry]\nExec=x\n' > "$WORK/pkg/share/pialite.desktop"
: > "$WORK/pkg/share/pialite.svg"
printf '#!/bin/sh\n[ "$1" = setup ] && [ -e %s/setup-fails ] && exit 1\necho new\n' "$WORK" > "$WORK/pkg/bin/pialite-guard"
cp "$WORK/pkg/bin/pialite-guard" "$WORK/pkg/bin/pialite-tray"
chmod +x "$WORK/pkg/bin/"*
# systemctl: the unit exists; "stop" fails on demand; "start" is logged
printf '#!/bin/sh\necho "$*" >> %s/systemctl.log\ncase "$1" in\n  stop) [ ! -e %s/stop-fails ];;\n  *) exit 0;;\nesac\n' "$WORK" "$WORK" > "$WORK/fake/systemctl"
chmod +x "$WORK/fake/systemctl"
old() {
    rm -rf /opt/pialite; mkdir -p /opt/pialite/bin
    printf '#!/bin/sh\necho old\n' > /opt/pialite/bin/pialite-guard; cp /opt/pialite/bin/pialite-guard /opt/pialite/bin/pialite-tray
    chmod +x /opt/pialite/bin/*
    : > "$WORK/systemctl.log"
}
run() { PATH="$WORK/fake:/usr/bin:/bin" sh "$WORK/pkg/install.sh" --upgrade >"$WORK/out" 2>&1; }
is_old() { [ "$(/opt/pialite/bin/pialite-guard)" = old ]; }
is_new() { [ "$(/opt/pialite/bin/pialite-guard)" = new ]; }

old; touch "$WORK/stop-fails"
run; rc=$?
check "guard won't stop: fails" [ "$rc" = 1 ]
check "guard won't stop: nothing replaced" is_old
check "guard won't stop: says so" grep -q "nothing was changed" "$WORK/out"
rm -f "$WORK/stop-fails"

old; touch "$WORK/setup-fails"
run; rc=$?
check "setup fails: fails" [ "$rc" = 1 ]
check "setup fails: previous programs back" is_old
check "setup fails: previous guard started" grep -q "^start pialite-guard.service" "$WORK/systemctl.log"
check "setup fails: says so" grep -q "previous version was put back" "$WORK/out"
check "setup fails: no copy left behind" [ ! -e /opt/pialite/bin.previous ]
rm -f "$WORK/setup-fails"

old
run; rc=$?
check "upgrade works: ok" [ "$rc" = 0 ]
check "upgrade works: new programs" is_new
check "upgrade works: previous copy removed" [ ! -e /opt/pialite/bin.previous ]
[ "$fails" = 0 ] || sed 's/^/    /' "$WORK/out"
[ "$fails" = 0 ] && echo "all install.sh upgrade checks passed"
exit "$fails"
