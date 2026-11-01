#!/usr/bin/env bash
# asn1peek AppImage 构建（Ubuntu 22.04 基线环境）
#
# 在 Ubuntu 22.04（jammy）无根 chroot（bubblewrap）中调用 scripts/build_appimage.sh，
# 使 PyInstaller 收集到的全部系统库均为 jammy 版本（GLIBC 符号 ≤ 2.35），
# 产物可在 Ubuntu 22.04+ 运行；同时复用宿主机的 uv 缓存与
# python-build-standalone 3.13 解释器（GLIBC ≤ 2.17），无需重复下载。
#
# 前置：bwrap（bubblewrap）、tar、curl、uv；建议已执行：
#   uv python install 3.13
#   UV_PROJECT_ENVIRONMENT=build/.venv-pbs313 uv sync --python 3.13 --group build
#
# 用法：bash scripts/build_appimage_jammy.sh
# 说明：首次运行会下载 jammy minimal rootfs 到 build/（约 60 MB），缓存复用。
set -euo pipefail
cd "$(dirname "$0")/.."

USER="${USER:-$(id -un)}"

HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
  x86_64)
    DEB_ARCH="amd64"
    GNU_ARCH="x86_64"
    ;;
  aarch64)
    DEB_ARCH="arm64"
    GNU_ARCH="aarch64"
    ;;
  *)
    echo "[!] 不支持的架构：$HOST_ARCH（仅支持 x86_64/aarch64）" >&2
    exit 1
    ;;
esac

ROOTFS="${JAMMY_ROOTFS:-$PWD/build/rootfs-jammy-$DEB_ARCH}"
TARBALL="build/jammy-rootfs-$DEB_ARCH.tar.xz"
ROOTFS_IMG="ubuntu-22.04-minimal-cloudimg-${DEB_ARCH}-root.tar.xz"
BASE_URL="https://cloud-images.ubuntu.com/minimal/releases/jammy/release"
VENV="${UV_PROJECT_ENVIRONMENT:-build/.venv-pbs313}"
VERSION="$("$VENV/bin/python" -c 'from asn1peek import __version__; print(__version__)')"

command -v bwrap >/dev/null 2>&1 || { echo "[!] 需要 bubblewrap（bwrap），请先安装"; exit 1; }
command -v uv >/dev/null 2>&1 || { echo "[!] 需要 uv"; exit 1; }

run_in_jammy() {
  bwrap --bind "$ROOTFS" / \
        --dev /dev --proc /proc --tmpfs /run --die-with-parent \
        --unshare-user --uid 0 --gid 0 \
        --bind "/home/$USER" "/home/$USER" --bind /tmp /tmp \
        --setenv HOME "/home/$USER" --setenv TERM dumb \
        --setenv LANG C.UTF-8 --setenv LC_ALL C.UTF-8 \
        --setenv PATH "/home/$USER/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
        "$@"
}

# ---- 1) 准备 jammy rootfs（缓存于 build/rootfs-jammy-<arch>）--------------
if [[ ! -x "$ROOTFS/bin/bash" ]]; then
  mkdir -p build
  if [[ ! -f "$TARBALL" ]]; then
    echo "[..] 下载 jammy minimal rootfs：$BASE_URL/$ROOTFS_IMG"
    curl -fL --retry 3 --max-time 900 -o "$TARBALL" "$BASE_URL/$ROOTFS_IMG"
  fi
  # 完整性校验（SHA256SUMS 获取失败时仅告警）
  # Rootfs release images are refreshed in place. Always refresh the checksum
  # manifest too; a stale cached manifest must not reject a current image (or
  # silently encourage skipping verification).
  curl -fsL --retry 3 --max-time 120 \
    -o build/SHA256SUMS.tmp "$BASE_URL/SHA256SUMS" 2>/dev/null \
    && mv build/SHA256SUMS.tmp build/SHA256SUMS \
    || { rm -f build/SHA256SUMS.tmp; echo "[!] 无法刷新 SHA256SUMS，将使用已有清单（若存在）"; }
  EXPECTED="$(awk -v img="$ROOTFS_IMG" \
    '{ name=$2; sub(/^\*/, "", name); if (name == img) print $1 }' \
    build/SHA256SUMS 2>/dev/null || true)"
  if [[ -n "$EXPECTED" ]]; then
    ACTUAL="$(sha256sum "$TARBALL" | awk '{print $1}')"
    [[ "$EXPECTED" == "$ACTUAL" ]] || { echo "[!] rootfs sha256 校验失败"; exit 1; }
    echo "[ok] rootfs sha256 校验通过"
  else
    echo "[!] SHA256SUMS 中未找到 $ROOTFS_IMG，拒绝不校验地解包" >&2
    exit 1
  fi
  echo "[..] 解包 rootfs → $ROOTFS"
  mkdir -p "$ROOTFS"
  # 允许个别设备节点的 mknod 失败（bwrap 会自备 /dev）
  LC_ALL=C tar -xJf "$TARBALL" -C "$ROOTFS" --numeric-owner 2>&1 | grep -vE 'Cannot (mknod|create symlink)' | tail -3 || true
  mkdir -p "$ROOTFS/home/$USER" "$ROOTFS/run"
  # dbus-1 aborts during QApplication startup if the minimal cloud root has no
  # machine-id. Generate a deterministic valid ID for the disposable build root.
  if [[ ! -s "$ROOTFS/etc/machine-id" ]]; then
    chmod u+w "$ROOTFS/etc/machine-id" 2>/dev/null || true
    printf '%s\n' '0123456789abcdef0123456789abcdef' > "$ROOTFS/etc/machine-id"
    chmod 0444 "$ROOTFS/etc/machine-id"
  fi
  # DNS：宿主 resolv.conf 直接覆盖（rootfs 内可能是指向 systemd-resolved 的悬空符号链接）
  rm -f "$ROOTFS/etc/resolv.conf"
  cp /etc/resolv.conf "$ROOTFS/etc/resolv.conf"
  # apt 源：补 universe（libxcb-cursor0 在 universe）
  cat > "$ROOTFS/etc/apt/sources.list" <<'EOF'
deb http://archive.ubuntu.com/ubuntu jammy main universe
deb http://archive.ubuntu.com/ubuntu jammy-updates main universe
deb http://security.ubuntu.com/ubuntu jammy-security main universe
EOF
fi
[[ -x "$ROOTFS/bin/bash" ]] || { echo "[!] rootfs 解包失败：$ROOTFS"; exit 1; }

# ---- 2) 准备 X11/Qt 基础依赖（jammy 版本；仅解包，不执行 postinst）------
# 说明：无根 userns（bwrap）里只有一个 uid/gid 映射，postinst 的 chown/
# 用户切换会失败（如 fontconfig-config）。改为：apt 只下载 deb →
# dpkg-deb -x 纯解包（库文件即可满足 PyInstaller 收集与 ldconfig 注册）→
# ldconfig 刷新缓存。binutils 一并放入，供构建脚本内 GLIBC 自检使用。
if ! [[ -f "$ROOTFS/usr/lib/${GNU_ARCH}-linux-gnu/libfontconfig.so.1" \
        && -f "$ROOTFS/usr/lib/${GNU_ARCH}-linux-gnu/libX11.so.6" \
        && -f "$ROOTFS/usr/lib/${GNU_ARCH}-linux-gnu/libxkbcommon.so.0" \
        && -f "$ROOTFS/usr/lib/${GNU_ARCH}-linux-gnu/libpng16.so.16" \
        && -f "$ROOTFS/usr/lib/${GNU_ARCH}-linux-gnu/libxcb-image.so.0" \
        && -f "$ROOTFS/usr/bin/objdump" && -x "$ROOTFS/usr/bin/file" ]]; then
  echo "[..] 在 jammy 环境内下载并解包构建期依赖（libxcb-cursor0、binutils、file 等）"
  run_in_jammy env DEBIAN_FRONTEND=noninteractive bash -c '
    set -e
    apt-get -o APT::Sandbox::User=root update -qq
    apt-get -o APT::Sandbox::User=root install -y -qq --download-only --no-install-recommends \
      libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 \
      libxcb-render-util0 libxcb-shape0 libxcb-xinerama0 libxkbcommon-x11-0 \
      libdbus-1-3 libssl3 libfontconfig1 libgl1 libegl1 \
      libx11-6 libxcb1 libxkbcommon0 libglib2.0-0 libstdc++6 \
      binutils file desktop-file-utils squashfs-tools
    for d in /var/cache/apt/archives/*.deb; do dpkg-deb -x "$d" /; done
    ldconfig'
fi

# ---- 3) 构建 ------------------------------------------------------------
# APPIMAGE_EXTRACT_AND_RUN=1：appimagetool 本身是 AppImage，在 bwrap 沙箱内
# 无 /dev/fuse，无法 FUSE 自挂载；改用解包直跑模式。
echo "[..] 在 jammy 环境内执行 scripts/build_appimage.sh"
run_in_jammy env UV_PROJECT_ENVIRONMENT="$VENV" UV_NO_PROGRESS=1 \
  APPIMAGE_EXTRACT_AND_RUN=1 \
  bash scripts/build_appimage.sh

echo "[..] 在相同 jammy 环境内执行 scripts/build_deb.sh"
run_in_jammy env UV_PROJECT_ENVIRONMENT="$VENV" UV_NO_PROGRESS=1 \
  bash scripts/build_deb.sh

echo "[..] 验证 AppImage 与 deb"
run_in_jammy env APPIMAGE_EXTRACT_AND_RUN=1 \
  bash scripts/verify_artifact.sh \
    "dist/asn1peek-${VERSION}-${HOST_ARCH}.AppImage" \
    "dist/asn1peek_${VERSION}_${DEB_ARCH}.deb" "$HOST_ARCH"

ls -lh dist/*.AppImage dist/*.deb
