#!/bin/sh
# install.sh --upgrade / --restore-previous (reviews G97-05, R98-02, R98-06,
# N99-02 .. N99-06, R10-02 .. R10-05, V11-01 .. V11-05): the new version is staged and the
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
LOCK=/run/pialite-install/lock

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
        echo "systemctl stop" >> $WORK/order.log
        [ -e $WORK/snap-stop ] && { rm -f $WORK/snap-stop; cp --sparse=always $WORK/opt.img $WORK/at-stop.img; }
        [ -e $WORK/fail-stop ] && exit 1
        echo inactive > $WORK/state
        [ ! -e $WORK/fail-stop-stopped ] ;;
    start)
        [ -e $WORK/fail-start ] && exit 1
        touch $WORK/started; echo active > $WORK/state ;;
    *) exit 0 ;;
esac
EOF
# cp / install / ln / mv / sed, when the file's text is in the arguments (empty
# = the next call), ONCE: fail-TOOL fails; kill-TOOL kills the installer
# instead of running (like a power cut); kill-after-TOOL runs, then kills it;
# snap-TOOL copies the disk image under /opt first (the power-cut test)
for t in cp install ln mv sed; do
    cat > "$WORK/fake/$t" <<EOF
#!/bin/sh
case "\$*" in *rollback*) echo "$t \$*" >> $WORK/order.log ;; esac
for how in fail kill kill-after snap; do
    f=$WORK/\$how-$t
    [ -e "\$f" ] || continue
    want=\$(cat "\$f")
    case "\$*" in *"\$want"*) ;; *) continue ;; esac
    rm -f "\$f"
    case \$how in
        fail) echo "$t: injected failure" >&2; exit 1 ;;
        kill) kill -9 \$PPID; exit 1 ;;
        kill-after) /bin/$t "\$@"; kill -9 \$PPID; exit 0 ;;
        snap) cp --sparse=always $WORK/opt.img $WORK/at-$t.img ;;
    esac
done
exec /bin/$t "\$@"
EOF
done
# sync: logs what is in place when it runs (the order of the barriers, V11-01);
# kill-after-marker-sync kills the installer right after the sync that follows
# its "guard-stopped" note - before the stop
cat > "$WORK/fake/sync" <<EOF
#!/bin/sh
echo "sync part=\$([ -e /opt/pialite.rollback.part ] && echo 1 || echo 0) roll=\$([ -e /opt/pialite.rollback ] && echo 1 || echo 0) marker=\$([ -e /opt/pialite.rollback/guard-stopped ] && echo 1 || echo 0)" >> $WORK/order.log
/bin/sync || exit 1
if [ -e $WORK/kill-after-marker-sync ] && [ -e /opt/pialite.rollback/guard-stopped ]; then
    rm -f $WORK/kill-after-marker-sync; kill -9 \$PPID
fi
EOF
chmod +x "$WORK/fake/"*

# a running previous version: block mode always, block in place, DNS only
# through the guard (or $WORK/status-before); no answer while its unit is
# stopped; after a restart it reports $WORK/status-after (if any)
old() {
    rm -rf /opt/pialite /opt/pialite.new /opt/pialite.rollback /opt/pialite.rollback.part /var/lib/pialite /usr/local/share \
        "$WORK"/fail-* "$WORK"/kill-* "$WORK"/started "$WORK"/status-after "$WORK"/status-before "$WORK"/no-unit \
        "$WORK"/hold-setup "$WORK"/in-setup "$WORK"/go "$WORK"/snap-* "$WORK"/fail-start
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
    : > "$WORK/order.log"
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
check "restore from an unfinished copy: says so" said "is unfinished"
check "restore from an unfinished copy: never stopped the guard" never_stopped
check "restore from an unfinished copy: the programs in use untouched" is_old
run; rc=$?
check "upgrade after an unfinished copy: works" [ "$rc" = 0 ]
check "upgrade after an unfinished copy: says it removed it" said "Removing an unfinished copy"
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
check "older unfinished copy: refused" all '[ "$rc" = 1 ]' 'said "incomplete or damaged - it is NOT used"'
check "older unfinished copy: never stopped the guard" never_stopped
check "older unfinished copy: programs untouched" is_old

# another installer is running: refused before anything is looked at or changed (R10-04)
for opt in --upgrade --uninstall --restore-previous; do
    old
    mkdir -p /run/pialite-install && chmod 0700 /run/pialite-install; exec 8>>"$LOCK"; flock -n 8
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

# --- review V11 -------------------------------------------------------------

# V11-01: the rename and the "guard-stopped" note are on disk before the stop
old
run; rc=$?
check "barriers: upgrade works" [ "$rc" = 0 ]
check "barriers: a sync after the rename, before the note" grep -q "sync part=0 roll=1 marker=0" "$WORK/order.log"
check "barriers: the last sync before the stop saw the note in place" \
    [ "$(sed -n '/systemctl stop/q;/^sync/p' "$WORK/order.log" | tail -1)" = "sync part=0 roll=1 marker=1" ]

# V11-01: what a power cut can leave if the disk kept the program change but
# not the rename / the note - the copy is never dropped as "nothing changed"
# (a real kill after the programs were replaced, then the lost writes undone)
lost_writes() { # $1 = rename | note
    old; printf '%s' "pialite.new/bin" > "$WORK/kill-after-mv"; run
    rm -f /opt/pialite.rollback/guard-stopped
    [ "$1" = rename ] && mv /opt/pialite.rollback /opt/pialite.rollback.part
    : > "$WORK/systemctl.log"
}
for lost in rename note; do
    lost_writes $lost
    run; rc=$?
    check "lost $lost, programs already replaced: the upgrade refuses" all '[ "$rc" = 1 ]' 'said restore-previous'
    check "lost $lost, programs already replaced: the copy is kept as the copy" all kept '[ ! -e /opt/pialite.rollback.part ]'
    run --restore-previous; rc=$?
    check "lost $lost, programs already replaced: restore-previous puts the old version back" \
        all '[ "$rc" = 0 ]' is_old 'said "protects as before"' no_temp
done
lost_writes note
run --restore-previous; rc=$?
check "lost note: restore-previous restores - never 'nothing to put back'" all '[ "$rc" = 0 ]' is_old 'never_said "Nothing to put back"'

# V11-02: a kept copy that lacks anything a restore needs, or no longer
# matches its manifest: refused BEFORE the guard is stopped or a file removed
kept_copy() { old; printf '%s' "pialite.new/bin" > "$WORK/kill-after-mv"; run; : > "$WORK/systemctl.log"; }
for damage in "rm -f /opt/pialite.rollback/bin/pialite-tray" "rm -f /opt/pialite.rollback/before-mode" \
    "rm -f /opt/pialite.rollback/install.json" "echo tampered >> /opt/pialite.rollback/bin/pialite-guard" \
    "echo bogus > /opt/pialite.rollback/before-dns" "rm -f /opt/pialite.rollback/manifest"; do
    kept_copy
    eval "$damage"
    # shellcheck disable=SC2034 # read in the check below (through all/eval)
    live=$(cksum < /opt/pialite/bin/pialite-guard)
    run --restore-previous; rc=$?
    check "damaged copy ($damage): refused" all '[ "$rc" = 1 ]' 'said "incomplete or damaged"'
    check "damaged copy ($damage): guard never stopped, programs in use untouched" \
        all never_stopped '[ "$(cksum < /opt/pialite/bin/pialite-guard)" = "$live" ]'
done
# an older installer's copy (no marker, no manifest) missing a program: refused too
kept_copy; rm -f /opt/pialite.rollback/complete /opt/pialite.rollback/manifest /opt/pialite.rollback/bin/pialite-tray
run --restore-previous; rc=$?
check "older copy missing a program: refused, never stopped" all '[ "$rc" = 1 ]' never_stopped
# ...while an older installer's complete copy is still restorable
kept_copy; rm -f /opt/pialite.rollback/complete /opt/pialite.rollback/manifest
run --restore-previous; rc=$?
check "older complete copy: restored" all '[ "$rc" = 0 ]' is_old

# V11-04: --restore-previous when the stop fails: the restart is checked and
# the copy always kept (nothing was put back)
stopped_copy() { old; touch "$WORK/kill-after-marker-sync"; run; : > "$WORK/systemctl.log"; }
stopped_copy; touch "$WORK/fail-stop-stopped" "$WORK/fail-start"
run --restore-previous; rc=$?
check "restore, stop fails, start fails: exit 1" [ "$rc" = 1 ]
check "restore, stop fails, start fails: says the guard remains stopped" said "remains STOPPED"
check "restore, stop fails, start fails: never 'protects as before'" never_said "protects as before"
check "restore, stop fails, start fails: copy kept" kept
stopped_copy; touch "$WORK/fail-stop-stopped"
echo '{"version":"old","mode":"off","armed":false,"dns_only_guard":true}' > "$WORK/status-after"
run --restore-previous; rc=$?
check "restore, stop fails, back in Off: not confirmed, copy kept" \
    all '[ "$rc" = 1 ]' 'said "Nothing was put back, but its protection could NOT be confirmed"' kept
stopped_copy; touch "$WORK/fail-stop-stopped"
run --restore-previous; rc=$?
check "restore, stop fails, restarted fine: says so, still exit 1, copy kept" \
    all '[ "$rc" = 1 ]' 'said "Nothing was put back, and its guard protects as before"' kept running
# ...and the same start failure during an upgrade
old; touch "$WORK/fail-stop-stopped" "$WORK/fail-start"
run; rc=$?
check "upgrade, stop fails, start fails: says so, copy kept" all '[ "$rc" = 1 ]' 'said "remains STOPPED"' kept is_old

# V11-05: the lock can't be opened - so not held - by another account, whatever the umask
old
(umask 000; run); rc=$?
check "lock under umask 000: upgrade works" [ "$rc" = 0 ]
check "lock under umask 000: its folder is root's alone" [ "$(stat -c '%u %a' /run/pialite-install)" = "0 700" ]
check "lock under umask 000: another account can't open it" \
    all '! setpriv --reuid=65534 --regid=65534 --clear-groups flock -n /run/pialite-install/lock true 2>/dev/null'
chmod 0777 /run/pialite-install; old; run
check "lock folder left open by others: closed again" [ "$(stat -c %a /run/pialite-install)" = 700 ]
rm -rf /run/pialite-install && : > /run/pialite-install; old
run; rc=$?
check "lock folder is a file: refused, nothing stopped" all '[ "$rc" = 1 ]' 'said "Could not set up the installer lock"' never_stopped is_old
rm -f /run/pialite-install

# V11-03: this test's own files are in its private /tmp
: > "$WORK/out"
check "work folder in the private /tmp" all 'case "$WORK" in /tmp/*) true ;; *) false ;; esac' \
    'grep -q "^pialite-test /tmp tmpfs " /proc/self/mounts'

# V11-01, for real: /opt on an ext4 disk image whose journal is written only
# when something syncs (commit=600); copies of the image taken at the stop
# and part-way through replacing the programs are exactly what a power cut
# at that moment leaves. (Skipped where loop devices aren't available.)
if command -v mkfs.ext4 >/dev/null 2>&1 && truncate -s 96M "$WORK/opt.img" && mkfs.ext4 -q -F "$WORK/opt.img" \
    && mount -o loop,commit=600 "$WORK/opt.img" /opt 2>/dev/null; then
    look() { mkdir -p "$WORK/look" && mount -o loop "$1" "$WORK/look"; } # replays the journal, like a reboot
    old; /bin/sync
    touch "$WORK/snap-stop"; printf '%s' "/usr/local/bin/pialite-tray" > "$WORK/snap-ln"
    run; rc=$?
    check "power cut: the upgrade itself works" [ "$rc" = 0 ]
    look "$WORK/at-stop.img"
    : > "$WORK/out"
    check "power cut at the stop: the copy, its name and its note are on disk" \
        all '[ -e "$WORK/look/pialite.rollback/complete" ]' '[ -e "$WORK/look/pialite.rollback/guard-stopped" ]' \
        '[ ! -e "$WORK/look/pialite.rollback.part" ]'
    umount "$WORK/look"
    # "reboot" from the image taken while the programs were being replaced
    umount /opt && mount -o loop,commit=600 "$WORK/at-ln.img" /opt
    echo active > "$WORK/state"; : > "$WORK/systemctl.log"
    run; rc=$?
    check "power cut mid-upgrade: the next upgrade refuses" all '[ "$rc" = 1 ]' 'said restore-previous'
    run --restore-previous; rc=$?
    check "power cut mid-upgrade: restore-previous puts the old version back" all '[ "$rc" = 0 ]' is_old 'said "protects as before"'
    umount /opt
else
    echo "SKIP: power-cut test (no loop device / mkfs.ext4 here)"
fi

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
