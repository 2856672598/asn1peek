#!/usr/bin/env bash
# Static and runtime checks for a built AppImage/deb pair.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ $# -lt 2 ]]; then
  echo "用法：$0 <AppImage> <deb> [目标架构 uname -m]" >&2
  exit 2
fi
APPIMAGE="$(realpath "$1")"
DEB="$(realpath "$2")"
TARGET_ARCH="${3:-$(uname -m)}"
case "$TARGET_ARCH" in
  x86_64) DEB_ARCH=amd64; ELF_PATTERN='x86-64' ;;
  aarch64) DEB_ARCH=arm64; ELF_PATTERN='ARM aarch64' ;;
  *) echo "[!] 不支持的目标架构：$TARGET_ARCH" >&2; exit 2 ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[..] 解包 AppImage 以检查 ELF"
(cd "$TMP" && APPIMAGE_EXTRACT_AND_RUN=1 "$APPIMAGE" --appimage-extract >/dev/null)
APPDIR="$TMP/squashfs-root"
[[ -d "$APPDIR" ]] || { echo "[!] AppImage 提取失败" >&2; exit 1; }

dpkg-deb -x "$DEB" "$TMP/deb"
DEB_CONTROL="$TMP/control"
dpkg-deb -e "$DEB" "$DEB_CONTROL"
grep -q "^Architecture: ${DEB_ARCH}$" "$DEB_CONTROL/control"
grep -q '^Depends:.*libc6 (>= 2.35)' "$DEB_CONTROL/control"

check_tree() {
  local tree="$1" label="$2"
  local found=0 max_glibc="" bad_arch=0
  while IFS= read -r -d '' f; do
    [[ "$(head -c 4 "$f")" == $'\x7fELF' ]] || continue
    found=1
    local desc
    desc="$(file -b "$f")"
    if [[ "$TARGET_ARCH" == x86_64 && "$desc" != *"$ELF_PATTERN"* ]] \
       || [[ "$TARGET_ARCH" == aarch64 && "$desc" != *"$ELF_PATTERN"* ]]; then
      echo "[!] 架构不匹配：$label/$f: $desc" >&2
      bad_arch=1
    fi
    local glibc
    glibc="$(objdump -T "$f" 2>/dev/null \
      | grep -oE 'GLIBC_[0-9]+\.[0-9]+' \
      | sort -Vu | tail -1 || true)"
    if [[ -n "$glibc" && ( -z "$max_glibc" || "$(printf '%s\n%s\n' "$max_glibc" "$glibc" | sort -V | tail -1)" == "$glibc" ) ]]; then
      max_glibc="$glibc"
    fi
  done < <(find "$tree" -type f -print0)

  (( found == 1 )) || { echo "[!] $label 中未找到 ELF" >&2; return 1; }
  (( bad_arch == 0 )) || return 1
  if [[ -n "$max_glibc" ]]; then
    local version="${max_glibc#GLIBC_}"
    [[ "$(printf '2.35\n%s\n' "$version" | sort -V | tail -1)" == "2.35" ]] \
      || { echo "[!] $label GLIBC 要求超过 2.35：$max_glibc" >&2; return 1; }
  fi
  if find "$tree" \( -type f -o -type l \) -name 'libstdc++.so*' -print -quit | grep -q .; then
    echo "[!] $label 不应捆绑 libstdc++.so*" >&2
    return 1
  fi
  echo "[ok] $label ELF 架构正确，最高 GLIBC=${max_glibc:-未知}，未捆绑 libstdc++"
}

check_tree "$APPDIR" AppImage
check_tree "$TMP/deb" deb

echo "[..] 校验版本入口"
export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=/dev/null}"
APP_VERSION="$(QT_QPA_PLATFORM=offscreen "$APPDIR/usr/bin/asn1peek" --version)"
grep -Fq 'exec /opt/asn1peek/asn1peek "$@"' "$TMP/deb/usr/bin/asn1peek"
DEB_VERSION="$(QT_QPA_PLATFORM=offscreen "$TMP/deb/opt/asn1peek/asn1peek" --version)"
[[ "$APP_VERSION" == "$DEB_VERSION" ]]
[[ "$APP_VERSION" == "$(uv run --frozen --no-sync python -c 'from asn1peek import __version__; print(__version__)')" ]]

echo "[..] 冒烟打开 samples/leaf.der（offscreen）"
QT_QPA_PLATFORM=offscreen "$APPDIR/usr/bin/asn1peek" --smoke-test "$PWD/samples/leaf.der"
QT_QPA_PLATFORM=offscreen "$TMP/deb/opt/asn1peek/asn1peek" --smoke-test "$PWD/samples/leaf.der"

echo "[ok] 产物验证通过：$(basename "$APPIMAGE") / $(basename "$DEB")"
