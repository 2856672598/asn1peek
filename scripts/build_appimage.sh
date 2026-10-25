#!/usr/bin/env bash
# asn1peek AppImage 一键出包。
#
# 产物：dist/asn1peek-<版本>-<架构>.AppImage
#
# 流程：PyInstaller（onedir）→ 组装 AppDir（usr/opt/asn1peek + AppRun）→
#       appimagetool 打包。
#
# 依赖：
#   - uv（或 pip）与项目 dev 依赖（pyinstaller 在 build 组内）
#   - appimagetool 与 type2 运行时（缺失时自动下载到 tools/bin/，需联网）
#   - GLIBC 基线（兼容 Ubuntu 22.04 = glibc 2.35）：
#     请勿用发行版系统 Python 打包——其 libpython 可能要求更高 GLIBC
#     （如 Ubuntu 26.04 系统 3.14 需 2.38）。建议用 uv 管理的
#     python-build-standalone 3.13（GLIBC ≤ 2.17）：
#       uv python install 3.13
#       UV_PROJECT_ENVIRONMENT=build/.venv-pbs313 uv sync --python 3.13 --group build
#       UV_PROJECT_ENVIRONMENT=build/.venv-pbs313 bash scripts/build_appimage.sh
#     脚本在打包前对产物做 GLIBC 符号自检（超基线仅警告，见输出）。
#   - 发行推荐直接运行 22.04 基线构建（自动使用 jammy 无根 chroot）：
#       bash scripts/build_appimage_jammy.sh
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="$(uv run python -c 'from importlib.metadata import version; print(version("asn1peek"))' 2>/dev/null || uv run python -c 'import asn1peek; print(asn1peek.__version__)')"
ARCH="$(uname -m)"
ROOT="$PWD"
APPDIR="build/appimage/AppDir"
OUT="dist"

# ---- 依赖检查 -----------------------------------------------------------
if ! uv run python -c 'import PyInstaller' 2>/dev/null; then
  echo "[..] 安装 PyInstaller（已加入 build 依赖组）"
  uv sync --group build 1>&2
fi

APPIMAGETOOL="tools/bin/appimagetool"
if [[ ! -x "$APPIMAGETOOL" ]]; then
  mkdir -p tools/bin
  # 用 AppImage/appimagetool（维护中）：其内嵌运行时为静态 squashfuse，
  # 产物无需 libfuse2——Ubuntu 24.04+ 默认不再预装 libfuse2，
  # 旧 AppImageKit 运行时会导致双击直接报 "libfuse.so.2" 错误。
  URL="https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-${ARCH}.AppImage"
  echo "[..] 下载 appimagetool：$URL"
  curl -fL --retry 3 -o "$APPIMAGETOOL.tmp" "$URL" \
    && chmod +x "$APPIMAGETOOL.tmp" && mv "$APPIMAGETOOL.tmp" "$APPIMAGETOOL" \
    || { rm -f "$APPIMAGETOOL.tmp"; echo "[!] 无网络且 tools/bin/ 下无 appimagetool，无法打包"; exit 1; }
fi

# type2 运行时（appimagetool 打包时嵌入）。预缓存可减少打包阶段对网络的依赖。
RUNTIME="tools/bin/runtime-${ARCH}"
if [[ ! -f "$RUNTIME" ]]; then
  mkdir -p tools/bin
  RT_URL="https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-${ARCH}"
  echo "[..] 下载 AppImage 运行时：$RT_URL"
  curl -fL --retry 3 -o "$RUNTIME.tmp" "$RT_URL" && mv "$RUNTIME.tmp" "$RUNTIME" \
    || { rm -f "$RUNTIME.tmp"; echo "[!] 运行时下载失败：appimagetool 将尝试自行获取（易受网络抖动影响）"; }
fi

# ---- PyInstaller onedir -------------------------------------------------
# 注意：入口用 packaging/launcher.py（app.py 含相对导入，不能直接作脚本入口）；
# 显式 --distpath 使产物落在 build/pyinstaller/asn1peek/（PyInstaller 6 布局：
# 可执行文件 + _internal/）。
rm -rf build/pyinstaller "$APPDIR"
uv run pyinstaller \
  --noconfirm --clean \
  --name asn1peek \
  --distpath build/pyinstaller \
  --workpath build/pyinstaller/_work \
  --paths src \
  --hidden-import asn1peek \
  --collect-submodules asn1peek \
  --add-data "src/asn1peek/core/data/oid_dumpasn1.json:asn1peek/core/data" \
  packaging/launcher.py 1>&2

# 不指定 --specpath，避免相对 --add-data 路径解析异常；
# 构建完成后删除自动生成的 spec 文件。
rm -f asn1peek.spec

# ---- 组装 AppDir --------------------------------------------------------
STAGE="$APPDIR/usr/opt/asn1peek"
mkdir -p "$STAGE" "$APPDIR/usr/share/applications" "$APPDIR/usr/share/icons/hicolor/256x256/apps" "$APPDIR/usr/bin"
cp -r build/pyinstaller/asn1peek/. "$STAGE/"
# 相对符号链接须相对 usr/bin 解析（../opt/...），否则指向不存在的 usr/bin/usr/...
ln -sf "../opt/asn1peek/asn1peek" "$APPDIR/usr/bin/asn1peek"
install -m 0755 packaging/asn1peek-AppRun "$APPDIR/AppRun"
install -m 0644 packaging/asn1peek.desktop "$APPDIR/usr/share/applications/asn1peek.desktop"
cp "$APPDIR/usr/share/applications/asn1peek.desktop" "$APPDIR/asn1peek.desktop"
if [[ -f assets/icon/asn1peek-256.png ]]; then
  install -m 0644 assets/icon/asn1peek-256.png \
    "$APPDIR/usr/share/icons/hicolor/256x256/apps/asn1peek.png"
  install -m 0644 assets/icon/asn1peek-256.png "$APPDIR/.DirIcon"
fi
[[ -f assets/icon/asn1peek.svg ]] && install -m 0644 assets/icon/asn1peek.svg "$APPDIR/asn1peek.svg"

# ---- GLIBC 基线自检（需可运行于 Ubuntu 22.04 / glibc 2.35）---------------
GLIBC_MAX=""
if command -v objdump >/dev/null 2>&1; then
  GLIBC_MAX="$(find "$STAGE" -type f \( -name 'asn1peek' -o -name '*.so*' \) -print0 \
    | while IFS= read -r -d '' f; do
        [[ "$(head -c 4 "$f")" == $'\x7fELF' ]] || continue
        objdump -T "$f" 2>/dev/null | grep -oE 'GLIBC_[0-9]+\.[0-9]+'
      done | sort -Vu | tail -1)"
fi
if [[ -z "$GLIBC_MAX" ]]; then
  echo "[..] 跳过 GLIBC 自检（objdump 不可用或未扫描到 ELF）"
else
  GLIBC_MAX="${GLIBC_MAX#GLIBC_}"   # 去掉前缀，得到如 "2.34"
  IFS=. read -r gmaj gmin <<< "$GLIBC_MAX"
  if (( gmaj > 2 || (gmaj == 2 && gmin > 35) )); then
    echo "[警告] 产物所需最高 GLIBC 符号为 $GLIBC_MAX（超过 Ubuntu 22.04 的 2.35）——"
    echo "        请改用 uv 管理的 python-build-standalone 重建（见脚本头部说明）。"
  else
    echo "[ok] GLIBC 基线自检通过：最高符号 $GLIBC_MAX ≤ 2.35（Ubuntu 22.04+ 可运行）"
  fi
fi

# ---- 打包 ---------------------------------------------------------------
mkdir -p "$OUT"
if [[ -f "$RUNTIME" ]]; then
  "$APPIMAGETOOL" -g --runtime-file "$RUNTIME" "$APPDIR" "$OUT/asn1peek-${VERSION}-${ARCH}.AppImage" 1>&2
else
  "$APPIMAGETOOL" -g "$APPDIR" "$OUT/asn1peek-${VERSION}-${ARCH}.AppImage" 1>&2
fi
echo "[ok] $OUT/asn1peek-${VERSION}-${ARCH}.AppImage"
