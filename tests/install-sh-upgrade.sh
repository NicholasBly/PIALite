#!/bin/sh
# install.sh --upgrade (reviews G97-05, R98-02, R98-06): the new version is
# staged before anything in use changes; a guard that won't stop means nothing
# is replaced; ANY failure after the stop puts the previous programs and
# settings back, starts the previous guard and says "as before" only when the
# guard shows its earlier block mode with its block in place.
# Fake systemctl, fake programs, and fake cp/install/ln/mv/sed that fail on
# demand. Runs in its own mount namespace with /opt, /usr/local, /var/lib and
# the unit folders hidden (tests/isolate.sh) - it can't touch a real
# installation. Run as root: sudo sh tests/install-sh-upgrade.sh
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/isolate.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT # only what this test made; the rest is tmpfs
fails=0
check() { # name, condition...
    name=$1; shift
    if "$@"; then echo "PASS: $name"; else echo "FAIL: $name"; fails=$((fails + 1)); sed 's/^/    | /' "$WORK/out"; fi
}

# the "new version" tarball: its guard's setup can fail, after changing the settings
mkdir -p "$WORK/pkg/bin" "$WORK/pkg/share" "$WORK/fake"
cp "$HERE/../packaging/linux/install.sh" "$WORK/pkg/"
printf '[Desktop Entry]\nExec=x\n' > "$WORK/pkg/share/pialite.desktop"
: > "$WORK/pkg/share/pialite.svg"
cat > "$WORK/pkg/bin/pialite-guard" <<EOF
#!/bin/sh
if [ "\$1" = setup ]; then
    echo new-settings > /var/lib/pialite/guard.json
    [ -e $WORK/fail-setup ] && { echo "setup: injected failure" >&2; exit 1; }
    exit 0
fi
echo new
EOF
cp "$WORK/pkg/bin/pialite-guard" "$WORK/pkg/bin/pialite-tray"
chmod +x "$WORK/pkg/bin/"*

# systemctl: the unit exists; stop fails on demand; start is logged
cat > "$WORK/fake/systemctl" <<EOF
#!/bin/sh
echo "\$*" >> $WORK/systemctl.log
case "\$1" in
    stop) [ ! -e $WORK/fail-stop ] ;;
    start) touch $WORK/started ;;
    *) exit 0 ;;
esac
EOF
# cp / install / ln / mv / sed: fail when $WORK/fail-TOOL exists and holds a
# text that is in the arguments (empty file = always)
for t in cp install ln mv sed; do
    cat > "$WORK/fake/$t" <<EOF
#!/bin/sh
if [ -e $WORK/fail-$t ]; then
    want=\$(cat $WORK/fail-$t)
    case "\$*" in *"\$want"*) echo "$t: injected failure" >&2; exit 1 ;; esac
fi
exec /bin/$t "\$@"
EOF
done
chmod +x "$WORK/fake/"*

old() { # a running previous version, block mode always, block in place
    rm -rf /opt/pialite /opt/pialite.new /opt/pialite.rollback /var/lib/pialite "$WORK"/fail-* "$WORK/started"
    mkdir -p /opt/pialite/bin /var/lib/pialite
    cat > /opt/pialite/bin/pialite-guard <<EOF
#!/bin/sh
if [ "\$1 \$2" = "status --json" ]; then
    if [ -e $WORK/started ] && [ -e $WORK/restarts-in-off ]; then
        echo '{"version":"old","mode":"off","armed":false}'
    else
        echo '{"version":"old","mode":"always","armed":true}'
    fi
    exit 0
fi
echo old
EOF
    cp /opt/pialite/bin/pialite-guard /opt/pialite/bin/pialite-tray
    chmod +x /opt/pialite/bin/*
    echo old-settings > /var/lib/pialite/guard.json
    : > "$WORK/systemctl.log"
}
run() { PATH="$WORK/fake:/usr/bin:/bin" PIALITE_ROLLBACK_WAIT=2 sh "$WORK/pkg/install.sh" --upgrade > "$WORK/out" 2>&1; }
is_old() { [ "$(/opt/pialite/bin/pialite-guard)" = old ] && [ "$(cat /var/lib/pialite/guard.json)" = old-settings ]; }
is_new() { [ "$(/opt/pialite/bin/pialite-guard)" = new ]; }
stopped() { grep -q "^stop pialite-guard" "$WORK/systemctl.log"; }
started() { grep -q "^start pialite-guard" "$WORK/systemctl.log"; }
said() { grep -q "$1" "$WORK/out"; }
no_temp() { [ ! -e /opt/pialite.new ] && [ ! -e /opt/pialite.rollback ]; }

# staging fails (disk full...): nothing in use changed, the guard never stopped
old; echo ".new/bin" > "$WORK/fail-install"
run; rc=$?
check "staging fails: exit 1" [ "$rc" = 1 ]
check "staging fails: old programs and settings" is_old
check "staging fails: the guard was never stopped" sh -c "! grep -q '^stop' '$WORK/systemctl.log'"
check "staging fails: nothing left over" no_temp

# the guard won't stop: nothing replaced
old; touch "$WORK/fail-stop"
run; rc=$?
check "won't stop: exit 1" [ "$rc" = 1 ]
check "won't stop: old programs and settings" is_old
check "won't stop: says so" said "nothing was changed"
check "won't stop: nothing left over" no_temp

# every step after the stop: the previous version back, its protection confirmed
for f in "mv:/opt/pialite.new/bin" "ln:/usr/local/bin/pialite-tray" "install:applications" "setup"; do
    old
    case "$f" in
        setup) touch "$WORK/fail-setup" ;;
        *) printf '%s' "${f#*:}" > "$WORK/fail-${f%%:*}" ;;
    esac
    run; rc=$?
    check "fails at $f: exit 1" [ "$rc" = 1 ]
    check "fails at $f: previous programs and settings back" is_old
    check "fails at $f: previous guard started" started
    check "fails at $f: confirmed as before" said "protects as before (block mode always)"
    check "fails at $f: nothing left over" no_temp
done

# back, running - but not protecting as before: NOT confirmed, files kept
old; touch "$WORK/fail-setup" "$WORK/restarts-in-off"
run; rc=$?
check "restarted in Off: exit 1" [ "$rc" = 1 ]
check "restarted in Off: NOT confirmed" said "could NOT be confirmed: it runs in block mode off instead of always"
check "restarted in Off: never says 'as before'" sh -c "! grep -q 'protects as before' '$WORK/out'"
check "restarted in Off: the copy is kept" [ -d /opt/pialite.rollback ]

# all fine
old
run; rc=$?
check "upgrade works: exit 0" [ "$rc" = 0 ]
check "upgrade works: new programs" is_new
check "upgrade works: nothing left over" no_temp

[ "$fails" = 0 ] && echo "all install.sh upgrade checks passed"
exit "$fails"
