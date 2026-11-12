#!/bin/sh
# install.sh --upgrade / --restore-previous (reviews G97-05, R98-02, R98-06,
# N99-02 .. N99-06): the new version is staged and the version in use copied
# before anything changes; a guard that won't stop, an unfinished earlier
# recovery, or a guard this script can't put back means nothing is touched;
# ANY failure after the stop puts the previous programs, settings and menu
# entry back, and "as before" is said only when every file went back and the
# guard shows its earlier block mode, block and DNS block.
# Fake systemctl, fake programs, and fake cp/install/ln/mv/sed that fail on
# demand. Runs in a private mount namespace with every folder install.sh can
# touch hidden (tests/isolate.sh) - it can't reach a real installation.
# Run as root: sudo sh tests/install-sh-upgrade.sh
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
MENU=/usr/local/share/applications/pialite.desktop

# the "new version" tarball: its guard's setup can fail, after changing the settings
mkdir -p "$WORK/pkg/bin" "$WORK/pkg/share" "$WORK/fake"
cp "$HERE/../packaging/linux/install.sh" "$WORK/pkg/"
printf '[Desktop Entry]\nExec=x\nName=new-menu\n' > "$WORK/pkg/share/pialite.desktop"
: > "$WORK/pkg/share/pialite.svg"
cat > "$WORK/pkg/bin/pialite-guard" <<EOF
#!/bin/sh
if [ "\$1" = setup ]; then
    echo new-settings > /var/lib/pialite/guard.json
    echo new-record > /var/lib/pialite/install.json
    [ -e $WORK/fail-setup ] && { echo "setup: injected failure" >&2; exit 1; }
    exit 0
fi
echo new
EOF
cp "$WORK/pkg/bin/pialite-guard" "$WORK/pkg/bin/pialite-tray"
chmod +x "$WORK/pkg/bin/"*

# systemctl: the unit exists unless $WORK/no-unit; stop fails on demand; start is logged
cat > "$WORK/fake/systemctl" <<EOF
#!/bin/sh
echo "\$*" >> $WORK/systemctl.log
case "\$1" in
    cat) [ ! -e $WORK/no-unit ] ;;
    stop) [ ! -e $WORK/fail-stop ] ;;
    start) touch $WORK/started ;;
    *) exit 0 ;;
esac
EOF
# cp / install / ln / mv / sed: fail ONCE when $WORK/fail-TOOL exists and its
# text is in the arguments (empty file = the next call)
for t in cp install ln mv sed; do
    cat > "$WORK/fake/$t" <<EOF
#!/bin/sh
if [ -e $WORK/fail-$t ]; then
    want=\$(cat $WORK/fail-$t)
    case "\$*" in *"\$want"*) rm -f $WORK/fail-$t; echo "$t: injected failure" >&2; exit 1 ;; esac
fi
exec /bin/$t "\$@"
EOF
done
chmod +x "$WORK/fake/"*

# a running previous version: block mode always, block in place, DNS only
# through the guard; after a restart it reports $WORK/status-after (if any)
old() {
    rm -rf /opt/pialite /opt/pialite.new /opt/pialite.rollback /var/lib/pialite /usr/local/share "$WORK"/fail-* "$WORK"/started \
        "$WORK"/status-after "$WORK"/no-unit
    mkdir -p /opt/pialite/bin /var/lib/pialite "$(dirname "$MENU")" /usr/local/bin
    cat > /opt/pialite/bin/pialite-guard <<EOF
#!/bin/sh
if [ "\$1 \$2" = "status --json" ]; then
    if [ -e $WORK/started ] && [ -e $WORK/status-after ]; then cat $WORK/status-after
    else echo '{"version":"old","mode":"always","armed":true,"dns_only_guard":true}'; fi
    exit 0
fi
echo old
EOF
    cp /opt/pialite/bin/pialite-guard /opt/pialite/bin/pialite-tray
    chmod +x /opt/pialite/bin/*
    echo old-settings > /var/lib/pialite/guard.json
    echo old-record > /var/lib/pialite/install.json
    printf '[Desktop Entry]\nName=old-menu\n' > "$MENU"
    ln -sf /opt/pialite/bin/pialite-tray /usr/local/bin/pialite-tray
    ln -sf /opt/pialite/bin/pialite-guard /usr/local/bin/pialite-guard
    : > "$WORK/systemctl.log"
}
run() { PATH="$WORK/fake:/usr/bin:/bin" PIALITE_ROLLBACK_WAIT=2 sh "$WORK/pkg/install.sh" "${1:---upgrade}" > "$WORK/out" 2>&1; }
is_old() {
    [ "$(/opt/pialite/bin/pialite-guard)" = old ] && [ "$(cat /var/lib/pialite/guard.json)" = old-settings ] \
        && [ "$(cat /var/lib/pialite/install.json)" = old-record ] && grep -q old-menu "$MENU"
}
is_new() { [ "$(/opt/pialite/bin/pialite-guard)" = new ] && grep -q new-menu "$MENU"; }
never_stopped() { ! grep -q '^stop' "$WORK/systemctl.log"; }
started() { grep -q "^start pialite-guard" "$WORK/systemctl.log"; }
said() { grep -q "$1" "$WORK/out"; }
never_said() { ! grep -q "$1" "$WORK/out"; }
no_temp() { [ ! -e /opt/pialite.new ] && [ ! -e /opt/pialite.rollback ]; }
kept() { [ -d /opt/pialite.rollback/bin ]; }

# staging fails (disk full...): nothing in use changed, the guard never stopped
old; echo ".new/bin" > "$WORK/fail-install"
run; rc=$?
check "staging fails: exit 1" [ "$rc" = 1 ]
check "staging fails: old programs, settings, menu" is_old
check "staging fails: the guard was never stopped" never_stopped
check "staging fails: nothing left over" no_temp

# the guard won't stop: nothing replaced
old; touch "$WORK/fail-stop"
run; rc=$?
check "won't stop: exit 1" [ "$rc" = 1 ]
check "won't stop: old programs, settings, menu" is_old
check "won't stop: says so" said "nothing was changed"
check "won't stop: nothing left over" no_temp

# a guard service whose program isn't ours to put back: untouched (N99-06)
old; rm -f /opt/pialite/bin/pialite-guard
run; rc=$?
check "foreign guard: exit 1" [ "$rc" = 1 ]
check "foreign guard: never stopped" never_stopped
check "foreign guard: says why" said "isn't an"

# every step after the stop: everything back, protection confirmed
for f in "mv:/opt/pialite.new/bin" "ln:/usr/local/bin/pialite-tray" "install:applications" "setup"; do
    old
    case "$f" in
        setup) touch "$WORK/fail-setup" ;;
        *) printf '%s' "${f#*:}" > "$WORK/fail-${f%%:*}" ;;
    esac
    run; rc=$?
    check "fails at $f: exit 1" [ "$rc" = 1 ]
    check "fails at $f: previous programs, settings, menu back" is_old
    check "fails at $f: previous guard started" started
    check "fails at $f: confirmed as before, DNS included" said "protects as before (block mode always, DNS only through the guard)"
    check "fails at $f: nothing left over" no_temp
done

# a setting that wasn't there before goes away again (N99-04)
old; rm -f /var/lib/pialite/install.json; touch "$WORK/fail-setup"
run; rc=$?
check "absent before: the new install.json is removed again" [ ! -e /var/lib/pialite/install.json ]

# back and armed - but its DNS block isn't: NOT "as before", copy kept (N99-02)
old; touch "$WORK/fail-setup"
echo '{"version":"old","mode":"always","armed":true,"dns_only_guard":false}' > "$WORK/status-after"
run; rc=$?
check "DNS block not back: exit 1" [ "$rc" = 1 ]
check "DNS block not back: NOT confirmed" said "DNS block / redirect is not on again"
check "DNS block not back: never 'as before'" never_said "protects as before"
check "DNS block not back: the copy is kept" kept

# ...and a retry doesn't overwrite that kept copy (N99-03)
sum=$(cd /opt/pialite.rollback && find . -type f -exec cat {} + | cksum)
rm -f "$WORK/fail-setup"
run; rc=$?
check "retry with a kept copy: refused" [ "$rc" = 1 ]
check "retry with a kept copy: says how to recover" said "restore-previous"
check "retry with a kept copy: copy untouched" [ "$(cd /opt/pialite.rollback && find . -type f -exec cat {} + | cksum)" = "$sum" ]
# --restore-previous puts it back once the guard protects as before
rm -f "$WORK/status-after"
run --restore-previous; rc=$?
check "restore-previous: exit 0" [ "$rc" = 0 ]
check "restore-previous: confirmed" said "protects as before"
check "restore-previous: copy removed" no_temp

# back in Off mode: NOT confirmed
old; touch "$WORK/fail-setup"
echo '{"version":"old","mode":"off","armed":false,"dns_only_guard":true}' > "$WORK/status-after"
run; rc=$?
check "restarted in Off: NOT confirmed" said "could NOT be confirmed: it runs in block mode off instead of always"
check "restarted in Off: the copy is kept" kept

# a restore step itself fails: not "put back completely", copy kept (N99-04)
old; touch "$WORK/fail-setup"; printf '%s' "rollback/share /opt" > "$WORK/fail-cp"
mkdir -p /opt/pialite/share/pialite && echo tarball > /opt/pialite/share/pialite/install-kind
run; rc=$?
check "restore step fails: exit 1" [ "$rc" = 1 ]
check "restore step fails: says what failed" said "could NOT be put back completely - these failed: /opt/pialite/share"
check "restore step fails: never 'as before'" never_said "protects as before"
check "restore step fails: the copy is kept" kept

# all fine
old
run; rc=$?
check "upgrade works: exit 0" [ "$rc" = 0 ]
check "upgrade works: new programs and menu" is_new
check "upgrade works: nothing left over" no_temp

[ "$fails" = 0 ] && echo "all install.sh upgrade checks passed"
exit "$fails"
