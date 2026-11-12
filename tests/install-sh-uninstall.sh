#!/bin/sh
# install.sh --uninstall with PIA Lite's program missing (review V95-05, F-08):
# it may only say "removed" when it could CHECK that nothing is left.
# Uses fake nft / systemctl; run as root on a machine WITHOUT PIA Lite installed
# (it deletes /opt/pialite and /usr/local/bin/pialite-* if they exist).
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
INSTALL="$HERE/../packaging/linux/install.sh"
FAKE=$(mktemp -d)
trap 'rm -rf "$FAKE"' EXIT
fails=0
case_() { # name, expected exit, expected text
    out=$(PATH="$FAKE:/usr/bin:/bin" sh "$INSTALL" --uninstall 2>&1); rc=$?
    if [ "$rc" = "$2" ] && printf '%s' "$out" | grep -q "$3"; then
        echo "PASS: $1"
    else
        echo "FAIL: $1 (exit $rc, wanted $2 and '$3')"; printf '%s\n' "$out" | sed 's/^/    /'; fails=$((fails + 1))
    fi
}
nft_tables() { printf '#!/bin/sh\n[ "$1 $2" = "list tables" ] && { printf "%s\\n" %s; exit 0; }\nexit 1\n' "%s" "$1" > "$FAKE/nft"; chmod +x "$FAKE/nft"; }
systemd_ok() { printf '#!/bin/sh\ncase "$1" in show) echo %s;; is-enabled) echo %s; [ %s = enabled ];; esac\n' "$1" "$2" "$2" > "$FAKE/systemctl"; chmod +x "$FAKE/systemctl"; }

nft_tables '"table inet filter" "table inet pialite"'; systemd_ok inactive disabled
case_ "a block table left" 1 "nftables table inet pialite"
nft_tables '"table inet filter"'; systemd_ok active enabled
case_ "the guard still running" 1 "pialite-guard.service is enabled"
printf '#!/bin/sh\necho "netlink: Error: Operation not permitted" >&2; exit 1\n' > "$FAKE/nft"
case_ "nftables can't be read" 1 "can't check"
rm -f "$FAKE/nft"
case_ "nft missing" 1 "nft) is not installed"
nft_tables '"table inet filter"'
printf '#!/bin/sh\necho "Failed to connect to bus" >&2; exit 1\n' > "$FAKE/systemctl"; chmod +x "$FAKE/systemctl"
case_ "systemd not answering" 1 "can't be asked"
systemd_ok inactive disabled
case_ "nothing left" 0 "PIA Lite removed."
[ "$fails" = 0 ] && echo "all install.sh uninstall checks passed"
exit "$fails"
