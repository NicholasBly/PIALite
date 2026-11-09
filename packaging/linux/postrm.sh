#!/bin/sh
# PIA Lite package: after the files are gone.
# deb: "remove" | "purge" | "upgrade" ...   rpm: 0 = erase, 1 = upgrade
case "$1" in
    purge|0)
        rm -rf /var/lib/pialite
        rm -f /etc/xdg/autostart/pialite-tray.desktop
        ;;
    remove)
        # settings stay for a reinstall (deb "purge" deletes them)
        rm -f /etc/xdg/autostart/pialite-tray.desktop
        ;;
esac
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
fi
exit 0
