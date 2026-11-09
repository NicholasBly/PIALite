#!/bin/sh
# PIA Lite package: after installing or upgrading the files.
# deb: "configure" [old-version]   rpm: 1 = install, 2 = upgrade
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
if [ -f /var/lib/pialite/install.json ]; then
    # upgrade: the same features as before; restarts the guard with the new program
    /usr/bin/pialite-guard setup || echo "PIA Lite: setting up after the upgrade failed - run: sudo pialite-guard setup -i"
else
    echo "PIA Lite is installed. Open 'PIA Lite' from your applications menu to choose"
    echo "the features you want (or run: sudo pialite-guard setup -i)."
fi
exit 0
