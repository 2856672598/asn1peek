#!/usr/bin/env bash
# 用户级安装 asn1peek 的 .desktop 与图标并注册文件关联。
#
# 用法：./scripts/install_desktop.sh [AppImage 绝对路径]
#   - 提供 AppImage 路径时，Exec 指向该文件；
#   - 未提供时假定 asn1peek 已在 PATH 中（pipx/系统安装形态）。
set -euo pipefail

DESKTOP_SRC="$(dirname "$0")/../packaging/asn1peek.desktop"
ICON_SRC="$(dirname "$0")/../assets/icon/asn1peek-256.png"

DATA_HOME="${XDG_DATA_HOME:-$HOME/.local/share}"
mkdir -p "$DATA_HOME/applications" "$DATA_HOME/icons/hicolor/256x256/apps"

if [[ -f "$ICON_SRC" ]]; then
  install -m 0644 "$ICON_SRC" "$DATA_HOME/icons/hicolor/256x256/apps/asn1peek.png"
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
if [[ -n "${1:-}" ]]; then
  APPIMAGE="$(readlink -f "$1")"
  [[ -f "$APPIMAGE" ]] || { echo "[!] AppImage 不存在：$APPIMAGE"; exit 1; }
  # AppImage 自解压形态：Exec 指向文件本体，@%U 处理文件参数
  sed -e "s|^Exec=.*|Exec=$APPIMAGE %f|" \
      -e "s|^TryExec=.*|TryExec=|" "$DESKTOP_SRC" > "$TMP"
else
  cp "$DESKTOP_SRC" "$TMP"
fi
install -m 0644 "$TMP" "$DATA_HOME/applications/asn1peek.desktop"

# 刷新缓存并设为默认打开方式
command -v update-desktop-database >/dev/null 2>&1 && \
  update-desktop-database "$DATA_HOME/applications" || true
if command -v xdg-mime >/dev/null 2>&1; then
  for m in application/pkix-cert application/x-x509-ca-cert application/pkcs8 \
           application/pkcs10 application/pkcs7-mime application/x-pem-file \
           application/x-der-file application/pkix-crl; do
    xdg-mime default asn1peek.desktop "$m" || true
  done
fi
echo "[ok] 已安装 .desktop 与图标，文件管理器可将 .der/.cer/.crt/.pem/.p7b/.crl 用 asn1peek 打开"
