#!/bin/sh
# Builds the Linux release files from target/release (run from the
# repository root after `cargo build --release`):
#   dist/pialite_VERSION_amd64.deb
#   dist/pialite-VERSION-1.x86_64.rpm          (needs rpmbuild)
#   dist/PIALite-VERSION-linux-x86_64.tar.gz   (install.sh inside)
# Usage: packaging/linux/build-packages.sh VERSION
set -eu
VERSION=${1:?usage: build-packages.sh VERSION}
ROOT=$(pwd)
L="$ROOT/packaging/linux"
DIST="$ROOT/dist"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$DIST"
for f in target/release/pialite-tray target/release/pialite-guard; do
    [ -x "$f" ] || { echo "missing $f - run cargo build --release first" >&2; exit 1; }
done

DESC_SHORT="Lightweight tray app for Private Internet Access"
DESC_LONG="Replaces PIA's own window with a small tray icon and panel. Optional
background guard: a kill switch (nftables) that blocks the internet until the
VPN connects, encrypted DNS over HTTPS to the provider you choose (NextDNS,
Cloudflare, Quad9, AdGuard, Google or your own) and a hotel Wi-Fi login helper.
Needs PIA's own app. Not affiliated with Private Internet Access."

# --- the files, as installed (shared by .deb and .rpm)
stage() { # $1 = folder, $2 = kind
    d=$1
    install -D -m 0755 target/release/pialite-tray "$d/usr/bin/pialite-tray"
    install -D -m 0755 target/release/pialite-guard "$d/usr/bin/pialite-guard"
    install -D -m 0644 "$L/pialite-guard.service" "$d/usr/lib/systemd/system/pialite-guard.service"
    install -D -m 0644 "$L/pialite-boot.service" "$d/usr/lib/systemd/system/pialite-boot.service"
    install -D -m 0644 "$L/pialite.desktop" "$d/usr/share/applications/pialite.desktop"
    install -D -m 0644 assets/pialite.svg "$d/usr/share/icons/hicolor/scalable/apps/pialite.svg"
    install -D -m 0644 LICENSE "$d/usr/share/doc/pialite/copyright"
    install -D -m 0644 README.md "$d/usr/share/doc/pialite/README.md"
    mkdir -p "$d/usr/share/pialite"
    printf '%s\n' "$2" > "$d/usr/share/pialite/install-kind"
}

# --- .deb
D="$WORK/deb"
stage "$D" deb
mkdir -p "$D/DEBIAN"
SIZE=$(du -sk "$D/usr" | cut -f1)
{
    echo "Package: pialite"
    echo "Version: $VERSION-1"
    echo "Architecture: amd64"
    echo "Maintainer: PIA Lite <NicholasBly@users.noreply.github.com>"
    echo "Installed-Size: $SIZE"
    echo "Depends: libc6, libfontconfig1, libxkbcommon0, libxkbcommon-x11-0, libx11-6, libxcursor1, libxrandr2, libxi6, nftables"
    echo "Recommends: pkexec | policykit-1, libwayland-client0"
    echo "Section: net"
    echo "Priority: optional"
    echo "Homepage: https://github.com/NicholasBly/PIALite"
    echo "Description: $DESC_SHORT"
    echo "$DESC_LONG" | sed 's/^/ /'
} > "$D/DEBIAN/control"
install -m 0755 "$L/postinst.sh" "$D/DEBIAN/postinst"
install -m 0755 "$L/prerm.sh" "$D/DEBIAN/prerm"
install -m 0755 "$L/postrm.sh" "$D/DEBIAN/postrm"
dpkg-deb --root-owner-group -Zxz --build "$D" "$DIST/pialite_${VERSION}_amd64.deb" >/dev/null
echo "built dist/pialite_${VERSION}_amd64.deb"

# --- .rpm
if command -v rpmbuild >/dev/null 2>&1; then
    R="$WORK/rpm"
    stage "$R/stage" rpm
    mkdir -p "$R/SPECS" "$R/RPMS" "$R/BUILD"
    {
        echo "Name: pialite"
        echo "Version: $VERSION"
        echo "Release: 1"
        echo "Summary: $DESC_SHORT"
        echo "License: GPL-3.0-or-later"
        echo "URL: https://github.com/NicholasBly/PIALite"
        echo "BuildArch: x86_64"
        echo "AutoReqProv: no"
        echo "Requires: fontconfig, libxkbcommon, libxkbcommon-x11, libX11, libXcursor, libXrandr, libXi, nftables"
        echo "Recommends: polkit"
        echo "%description"
        echo "$DESC_LONG"
        echo "%install"
        echo "cp -a $R/stage/. %{buildroot}/"
        echo "%files"
        (cd "$R/stage" && find . -type f | sed 's|^\.||' | sort)
        echo "%post"
        cat "$L/postinst.sh"
        echo "%preun"
        cat "$L/prerm.sh"
        echo "%postun"
        cat "$L/postrm.sh"
    } > "$R/SPECS/pialite.spec"
    rpmbuild -bb --quiet --define "_topdir $R" --define "_build_id_links none" --define "__strip /bin/true" "$R/SPECS/pialite.spec"
    cp "$R"/RPMS/x86_64/pialite-"$VERSION"-1.x86_64.rpm "$DIST/"
    echo "built dist/pialite-$VERSION-1.x86_64.rpm"
else
    echo "rpmbuild not found - .rpm skipped" >&2
fi

# --- .tar.gz (portable: run bin/pialite-tray as is, or sudo ./install.sh)
N="PIALite-$VERSION-linux-x86_64"
T="$WORK/$N"
install -D -m 0755 target/release/pialite-tray "$T/bin/pialite-tray"
install -D -m 0755 target/release/pialite-guard "$T/bin/pialite-guard"
# run from this folder = the portable tray (install.sh installs it properly)
printf 'portable\n' > "$T/bin/install-kind"
install -D -m 0644 "$L/pialite.desktop" "$T/share/pialite.desktop"
install -D -m 0644 assets/pialite.svg "$T/share/pialite.svg"
install -m 0755 "$L/install.sh" "$T/install.sh"
install -m 0644 README.md LICENSE "$T/"
tar -C "$WORK" --owner=0 --group=0 -czf "$DIST/$N.tar.gz" "$N"
echo "built dist/$N.tar.gz"
