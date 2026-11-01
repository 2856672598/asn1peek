#!/usr/bin/env bash
# Build a Debian package from the shared PyInstaller onedir payload.
set -euo pipefail
cd "$(dirname "$0")/.."

ARCH="$(dpkg --print-architecture)"
case "$ARCH" in
  amd64|arm64) ;;
  *) echo "[!] 不支持的 deb 架构：$ARCH" >&2; exit 1 ;;
esac

VERSION="$(uv run --frozen --no-sync python -c 'from asn1peek import __version__; print(__version__)')"
ROOT="build/deb-root"
PKG="asn1peek_${VERSION}_${ARCH}.deb"

bash scripts/build_bundle.sh
rm -rf "$ROOT"
mkdir -p "$ROOT/DEBIAN" "$ROOT/opt/asn1peek" \
  "$ROOT/usr/bin" "$ROOT/usr/share/applications" \
  "$ROOT/usr/share/icons/hicolor/256x256/apps" "$ROOT/usr/share/doc/asn1peek"

cp -a build/pyinstaller/asn1peek/. "$ROOT/opt/asn1peek/"
cat > "$ROOT/usr/bin/asn1peek" <<'WRAPPER'
#!/bin/sh
exec /opt/asn1peek/asn1peek "$@"
WRAPPER
chmod 0755 "$ROOT/usr/bin/asn1peek"
install -m 0644 packaging/asn1peek.desktop "$ROOT/usr/share/applications/asn1peek.desktop"
install -m 0644 assets/icon/asn1peek-256.png \
  "$ROOT/usr/share/icons/hicolor/256x256/apps/asn1peek.png"
install -m 0644 LICENSE "$ROOT/usr/share/doc/asn1peek/copyright"

INSTALLED_SIZE="$(du -sk "$ROOT/opt" "$ROOT/usr" | awk '{sum += $1} END {print sum}')"
LIBSTDCXX_MAJOR="$(dpkg-query -W -f='${Version}' libstdc++6 | sed -E 's/^[0-9]+://; s/^([0-9]+).*/\1/')"
cat > "$ROOT/DEBIAN/control" <<CONTROL
Package: asn1peek
Version: ${VERSION}
Architecture: ${ARCH}
Section: utils
Priority: optional
Installed-Size: ${INSTALLED_SIZE}
Depends: libc6 (>= 2.35), libstdc++6 (>= ${LIBSTDCXX_MAJOR}), libxcb-cursor0, libxcb-icccm4, libxcb-image0, libxcb-keysyms1, libxcb-randr0, libxcb-render-util0, libxcb-shape0, libxcb-xinerama0, libxkbcommon-x11-0, libgl1, libegl1, libfontconfig1, libdbus-1-3, libglib2.0-0
Description: ASN.1 data viewer with synchronized tree and hex views
 Inspect DER, BER, PEM and PKCS#7 data in a synchronized tree and hex view.
CONTROL

cat > "$ROOT/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
fi
exit 0
POSTINST
cat > "$ROOT/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if command -v update-desktop-database >/dev/null 2>&1; then
  update-desktop-database -q /usr/share/applications || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
  gtk-update-icon-cache -q -t -f /usr/share/icons/hicolor || true
fi
exit 0
POSTRM
chmod 0755 "$ROOT/DEBIAN/postinst" "$ROOT/DEBIAN/postrm"

mkdir -p dist
dpkg-deb --build --root-owner-group "$ROOT" "dist/$PKG"
echo "[ok] dist/$PKG"
