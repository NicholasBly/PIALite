#!/bin/sh
# PIA Lite package: after installing or upgrading the files.
# deb: "configure" [old-version]   rpm: 1 = install, 2 = upgrade
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ -f /var/lib/pialite/install.json ]; then
    # upgrade: the same features as before; restarts the guard with the new program
    # a failed setup is a failed install - not a line nobody reads (review V95-09)
    if ! /usr/bin/pialite-guard setup; then
        echo "PIA Lite: setting up after the upgrade FAILED (see above and /var/lib/pialite/guard.log)." >&2
        echo "Fix the cause and run: sudo pialite-guard setup -i  (or: sudo pialite-guard unlock if you are offline)" >&2
        exit 1
    fi
else
    echo "PIA Lite is installed. Open 'PIA Lite' from your applications menu to choose"
    echo "the features you want (or run: sudo pialite-guard setup -i)."
fi
exit 0
