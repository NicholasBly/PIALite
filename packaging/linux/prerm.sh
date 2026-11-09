#!/bin/sh
# PIA Lite package: before the files are removed or replaced.
# deb: "remove" | "upgrade" ...   rpm: 0 = erase, 1 = upgrade
case "$1" in
    remove|0)
        # the block rules must not outlive the program that can remove them
        if ! /usr/bin/pialite-guard teardown --keep-config; then
            echo "PIA Lite: could NOT remove its block rules - run 'sudo pialite-guard unlock', then remove the package again." >&2
            exit 1
        fi
        ;;
    *)
        # upgrade: nothing - the new package's script restarts the guard
        # with the new program (rpm runs it BEFORE this one)
        ;;
esac
exit 0
