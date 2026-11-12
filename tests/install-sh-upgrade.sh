#!/bin/sh
# install.sh --upgrade / --restore-previous (reviews G97-05, R98-02, R98-06,
# N99-02 .. N99-06, R10-02 .. R10-05): the new version is staged and the
# version in use copied - complete and marked - before anything changes; a
# guard that won't stop, an unfinished earlier recovery, a guard this script
# can't put back, or another installer running means nothing is touched; ANY
# failure after the stop puts the previous programs, settings and menu entry
# back, and "as before" is said only when every file went back and the guard
# shows its earlier block mode, block and DNS block.
# Fake systemctl (with a unit state), fake programs, and fake cp/install/ln/mv/
# sed that fail - or kill the installer, like a power cut - on demand. Runs in
# a private mount namespace with every folder install.sh can touch hidden
# (tests/isolate.sh) - it can't reach a real installation.
# Run as root: sudo sh tests/install-sh-upgrade.sh
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
. "$HERE/isolate.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT # only what this test made; the rest is tmpfs
fails=0
all() { for c in "$@"; do eval "$c" || return 1; done; } # all 'COND' 'COND'...: every one holds
check() { # name, condition...
    name=$1; shift
    if "$@"; then echo "PASS: $name"; else echo "FAIL: $name"; fails=$((fails + 1)); sed 's/^/    | /' "$WORK/out"; fi
}
MENU=/usr/local/share/applications/pialite.desktop
LOCK=/run/pialite-install.lock

# the "new version" tarball: its guard's setup can fail (after changing the
# settings), or wait at a barrier
mkdir -p "$WORK/pkg/bin" "$WORK/pkg/share" "$WORK/fake"
cp "$HERE/../packaging/linux/install.sh" "$WORK/pkg/"
printf '[Desktop Entry]\nExec=x\nName=new-menu\n' > "$WORK/pkg/share/pialite.desktop"
: > "$WORK/pkg/share/pialite.svg"
cat > "$WORK/pkg/bin/pialite-guard" <<EOF
#!/bin/sh
if [ "\$1" = setup ]; then
    echo new-settings > /var/lib/pialite/guard.json
    echo new-record > /var/lib/pialite/install.json
    if [ -e $WORK/hold-setup ]; then
        : > $WORK/in-setup
        n=0; while [ ! -e $WORK/go ] && [ \$n -lt 300 ]; do sleep 0.1; n=\$((n + 1)); done
    fi
    [ -e $WORK/fail-setup ] && { echo "setup: injected failure" >&2; exit 1; }
    exit 0
fi
echo new
EOF
cp "$WORK/pkg/bin/pialite-guard" "$WORK/pkg/bin/pialite-tray"
chmod +x "$WORK/pkg/bin/"*

# systemctl: the unit exists unless $WORK/no-unit; its state is in $WORK/state.
# stop fails on demand - leaving it running (fail-stop) or after stopping it
# (fail-stop-stopped); start is logged
cat > "$WORK/fake/systemctl" <<EOF
#!/bin/sh
echo "\$*" >> $WORK/systemctl.log
case "\$1" in
    cat) [ ! -e $WORK/no-unit ] ;;
    show) cat $WORK/state ;;
    stop)
        [ -e $WORK/fail-stop ] && exit 1
        echo inactive > $WORK/state
        [ ! -e $WORK/fail-stop-stopped ] ;;
    start) touch $WORK/started; echo active > $WORK/state ;;
    *) exit 0 ;;
esac
EOF
# cp / install / ln / mv / sed, when the file's text is in the arguments (empty
# = the next call), ONCE: fail-TOOL fails; kill-TOOL kills the installer
# instead of running (like a power cut); kill-after-TOOL runs, then kills it
for t in cp install ln mv sed; do
    cat > "$WORK/fake/$t" <<EOF
#!/bin/sh
for how in fail kill kill-after; do
    f=$WORK/\$how-$t
    [ -e "\$f" ] || continue
    want=\$(cat "\$f")
    case "\$*" in *"\$want"*) ;; *) continue ;; esac
    rm -f "\$f"
    case \$how in
        fail) echo "$t: injected failure" >&2; exit 1 ;;
        kill) kill -9 \$PPID; exit 1 ;;
        kill-after) /bin/$t "\$@"; kill -9 \$PPID; exit 0 ;;
    esac
done
exec /bin/$t "\$@"
EOF
done
chmod +x "$WORK/fake/"*

# a running previous version: block mode always, block in place, DNS only
# through the guard (or $WORK/status-before); no answer while its unit is
# stopped; after a restart it reports $WORK/status-after (if any)
old() {
    rm -rf /opt/pialite /opt/pialite.new /opt/pialite.rollback /opt/pialite.rollback.part /var/lib/pialite /usr/local/share \
        "$WORK"/fail-* "$WORK"/kill-* "$WORK"/started "$WORK"/status-after "$WORK"/status-before "$WORK"/no-unit \
        "$WORK"/hold-setup "$WORK"/in-setup "$WORK"/go
    mkdir -p /opt/pialite/bin /var/lib/pialite "$(dirname "$MENU")" /usr/local/bin
    cat > /opt/pialite/bin/pialite-guard <<EOF
#!/bin/sh
if [ "\$1 \$2" = "status --json" ]; then
    [ "\$(cat $WORK/state)" = active ] || exit 1
    if [ -e $WORK/started ] && [ -e $WORK/status-after ]; then cat $WORK/status-after
    elif [ -e $WORK/status-before ]; then cat $WORK/status-before
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
    echo active > "$WORK/state"
    : > "$WORK/systemctl.log"
}
run() {
    PATH="$WORK/fake:/usr/bin:/bin" PIALITE_ROLLBACK_WAIT=2 sh "$WORK/pkg/install.sh" "${1:---upgrade}" > "$WORK/out" 2>&1
    rc=$?
    flock -w 10 "$LOCK" true # a killed installer's last helper may hold the lock a moment longer
    return $rc
}
is_old() {
    [ "$(/opt/pialite/bin/pialite-guard)" = old ] && [ "$(cat /var/lib/pialite/guard.json)" = old-settings ] \
        && [ "$(cat /var/lib/pialite/install.json)" = old-record ] && grep -q old-menu "$MENU"
}
is_new() { [ "$(/opt/pialite/bin/pialite-guard)" = new ] && grep -q new-menu "$MENU"; }
never_stopped() { ! grep -q '^stop' "$WORK/systemctl.log"; }
started() { grep -q "^start pialite-guard" "$WORK/systemctl.log"; }
said() { grep -q "$1" "$WORK/out"; }
never_said() { ! grep -q "$1" "$WORK/out"; }
no_temp() { [ ! -e /opt/pialite.new ] && [ ! -e /opt/pialite.rollback ] && [ ! -e /opt/pialite.rollback.part ]; }
kept() { [ -d /opt/pialite.rollback/bin ]; }
running() { [ "$(cat "$WORK/state")" = active ]; }

# staging fails (disk full...): nothing in use changed, the guard never stopped
old; echo ".new/bin" > "$WORK/fail-install"
run; rc=$?
check "staging fails: exit 1" [ "$rc" = 1 ]
check "staging fails: old programs, settings, menu" is_old
check "staging fails: the guard was never stopped" never_stopped
check "staging fails: nothing left over" no_temp

# the guard won't stop, and is still running: nothing replaced, its protection checked (R10-03)
old; touch "$WORK/fail-stop"
run; rc=$?
check "won't stop: exit 1" [ "$rc" = 1 ]
check "won't stop: old programs, settings, menu" is_old
check "won't stop: says it is still running" said "could not be stopped (it is still running)"
check "won't stop: no program files replaced, protection confirmed" said "No program files were replaced, and its guard protects as before"
check "won't stop: nothing left over" no_temp

# the stop "fails" but did stop it: started again and checked, not left stopped (R10-03)
old; touch "$WORK/fail-stop-stopped"
run; rc=$?
check "stop fails after stopping: exit 1" [ "$rc" = 1 ]
check "stop fails after stopping: old programs" is_old
check "stop fails after stopping: says what systemd reports" said "now reports it as inactive - starting it again"
check "stop fails after stopping: the guard runs again" running
check "stop fails after stopping: protection confirmed" said "No program files were replaced, and its guard protects as before"
check "stop fails after stopping: nothing left over" no_temp
# ...and when it comes back without its block: NOT confirmed, the copy kept
old; touch "$WORK/fail-stop-stopped"
echo '{"version":"old","mode":"off","armed":false,"dns_only_guard":true}' > "$WORK/status-after"
run; rc=$?
check "stop fails, comes back in Off: exit 1" [ "$rc" = 1 ]
check "stop fails, comes back in Off: NOT confirmed" said "protection could NOT be confirmed: it runs in block mode off instead of always"
check "stop fails, comes back in Off: the copy is kept" kept

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

# an old guard that didn't report its DNS block: PARTIALLY VERIFIED, never "as before" (R10-05)
old; touch "$WORK/fail-setup"
echo '{"version":"old","mode":"always","armed":true}' > "$WORK/status-before"
run; rc=$?
check "DNS state unknown before: exit 1" [ "$rc" = 1 ]
check "DNS state unknown before: PARTIALLY VERIFIED" said "PARTIALLY VERIFIED"
check "DNS state unknown before: never 'as before'" never_said "protects as before"
check "DNS state unknown before: previous programs back" is_old

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

# killed (power cut) while the copy is being made - programs copied, settings
# not yet: the copy isn't marked complete, nothing was stopped (R10-02)
old; printf '%s' "rollback.part/guard.json" > "$WORK/kill-cp"
run
check "killed while copying: the guard was never stopped" never_stopped
check "killed while copying: old programs, settings, menu" is_old
check "killed while copying: only an unfinished copy is left" all '[ -d /opt/pialite.rollback.part/bin ]' '[ ! -e /opt/pialite.rollback ]'
run --restore-previous; rc=$?
check "restore from an unfinished copy: refused" [ "$rc" = 1 ]
check "restore from an unfinished copy: says so" said "is incomplete"
check "restore from an unfinished copy: never stopped the guard" never_stopped
check "restore from an unfinished copy: the programs in use untouched" is_old
run; rc=$?
check "upgrade after an unfinished copy: works" [ "$rc" = 0 ]
check "upgrade after an unfinished copy: says it removed it" said "Removing an incomplete copy"
check "upgrade after an unfinished copy: new programs" is_new
check "upgrade after an unfinished copy: nothing left over" no_temp

# killed right after the copy was completed, before the stop: nothing to put back
old; printf '%s' "rollback.part /opt/pialite.rollback" > "$WORK/kill-after-mv"
run
check "killed after copying: never stopped" never_stopped
check "killed after copying: a complete copy, not marked as stopped" all '[ -e /opt/pialite.rollback/complete ]' '[ ! -e /opt/pialite.rollback/guard-stopped ]'
run --restore-previous; rc=$?
check "restore when nothing was changed: exit 0" [ "$rc" = 0 ]
check "restore when nothing was changed: says so" said "Nothing to put back"
check "restore when nothing was changed: never stopped the guard" never_stopped
check "restore when nothing was changed: copy removed, programs untouched" all no_temp is_old
old; printf '%s' "rollback.part /opt/pialite.rollback" > "$WORK/kill-after-mv"
run; run; rc=$?
check "upgrade after a copy that changed nothing: works" all '[ "$rc" = 0 ]' is_new no_temp

# killed after the stop, half-way through replacing the programs: the next
# upgrade refuses; --restore-previous puts the old version back
old; printf '%s' "pialite.new/bin" > "$WORK/kill-after-mv"
run
check "killed mid-upgrade: the copy is complete and marked as stopped" all '[ -e /opt/pialite.rollback/complete ]' '[ -e /opt/pialite.rollback/guard-stopped ]'
run; rc=$?
check "killed mid-upgrade: the next upgrade refuses" all '[ "$rc" = 1 ]' 'said restore-previous'
run --restore-previous; rc=$?
check "killed mid-upgrade: restore-previous exit 0" [ "$rc" = 0 ]
check "killed mid-upgrade: old programs, settings, menu back" is_old
check "killed mid-upgrade: confirmed as before" said "protects as before (block mode always, DNS only through the guard)"
check "killed mid-upgrade: nothing left over" no_temp

# a copy an older installer left unfinished (no marker, empty last file): never used
old; mkdir -m 0700 /opt/pialite.rollback && cp -a /opt/pialite/bin /opt/pialite.rollback/bin && : > /opt/pialite.rollback/before-dns
run --restore-previous; rc=$?
check "older unfinished copy: refused" all '[ "$rc" = 1 ]' 'said "incomplete - it is NOT used"'
check "older unfinished copy: never stopped the guard" never_stopped
check "older unfinished copy: programs untouched" is_old

# another installer is running: refused before anything is looked at or changed (R10-04)
for opt in --upgrade --uninstall --restore-previous; do
    old
    exec 8>>"$LOCK"; flock -n 8
    run "$opt"; rc=$?
    exec 8>&-
    check "locked, $opt: refused" [ "$rc" = 1 ]
    check "locked, $opt: says another one is running" said "Another PIA Lite install"
    check "locked, $opt: nothing stopped or changed" all never_stopped is_old no_temp
done
# two at once: the second stops at once and never touches the first one's files
old; touch "$WORK/hold-setup"
PATH="$WORK/fake:/usr/bin:/bin" PIALITE_ROLLBACK_WAIT=2 sh "$WORK/pkg/install.sh" --upgrade > "$WORK/out-first" 2>&1 &
first=$!
n=0; while [ ! -e "$WORK/in-setup" ] && [ $n -lt 300 ]; do sleep 0.1; n=$((n + 1)); done
staged=$(cd /opt && find pialite.new pialite.rollback -type f -exec cat {} + 2>/dev/null | cksum)
PATH="$WORK/fake:/usr/bin:/bin" sh "$WORK/pkg/install.sh" --upgrade > "$WORK/out" 2>&1; rc=$?
check "second installer at once: refused" all '[ "$rc" = 1 ]' 'said "Another PIA Lite install"'
check "second installer at once: the first one's staging and copy untouched" \
    [ "$(cd /opt && find pialite.new pialite.rollback -type f -exec cat {} + 2>/dev/null | cksum)" = "$staged" ]
check "second installer at once: stopped nothing itself" [ "$(grep -c '^stop' "$WORK/systemctl.log")" = 1 ]
touch "$WORK/go"; wait "$first"; rc=$?
cp "$WORK/out-first" "$WORK/out"
check "the first installer finishes: exit 0" [ "$rc" = 0 ]
check "the first installer finishes: new programs" is_new
check "the first installer finishes: nothing left over" no_temp

# all fine
old
run; rc=$?
check "upgrade works: exit 0" [ "$rc" = 0 ]
check "upgrade works: new programs and menu" is_new
check "upgrade works: nothing left over" no_temp

: > "$WORK/out"
check "nothing was created outside the hidden folders" still_isolated
[ "$fails" = 0 ] && echo "all install.sh upgrade checks passed"
exit "$fails"
