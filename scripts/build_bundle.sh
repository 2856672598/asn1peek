#!/usr/bin/env bash
# Build the shared PyInstaller onedir payload used by AppImage and deb.
set -euo pipefail
cd "$(dirname "$0")/.."

ROOT="$PWD"
DIST="build/pyinstaller"
APP="${DIST}/asn1peek"
STAMP="${DIST}/.bundle-inputs.sha256"

GLIBC_VERSION="$(getconf GNU_LIBC_VERSION | awk '{print $2}')"
GLIBC_MAJOR="${GLIBC_VERSION%%.*}"
GLIBC_MINOR="${GLIBC_VERSION#*.}"
GLIBC_MINOR="${GLIBC_MINOR%%.*}"
if (( GLIBC_MAJOR > 2 || (GLIBC_MAJOR == 2 && GLIBC_MINOR > 35) )); then
  echo "[!] 必须在 Ubuntu 22.04 / glibc 2.35 基线中构建；当前是 glibc $GLIBC_VERSION" >&2
  echo "    请使用 bash scripts/build_appimage_jammy.sh，或在 Jammy 容器/runner 中执行。" >&2
  exit 1
fi

mkdir -p build
INPUTS_HASH="$(find src packaging/launcher.py pyproject.toml uv.lock -type f -print0 \
  | sort -z \
  | xargs -0 sha256sum \
  | sha256sum \
  | awk '{print $1}')"

if [[ "${FORCE:-0}" != 1 && -x "$APP/asn1peek" && -f "$STAMP" \
      && "$(cat "$STAMP")" == "$INPUTS_HASH" ]]; then
  echo "[ok] 复用 PyInstaller bundle（输入未变化）"
  exit 0
fi

echo "[..] PyInstaller onedir 构建开始"
rm -rf "$DIST"
uv run --frozen --group build pyinstaller \
  --noconfirm --clean \
  --name asn1peek \
  --distpath "$DIST" \
  --workpath "$DIST/_work" \
  --paths src \
  --hidden-import asn1peek \
  --collect-submodules asn1peek \
  --add-data "src/asn1peek/core/data/oid_dumpasn1.json:asn1peek/core/data" \
  packaging/launcher.py 1>&2

rm -f "$ROOT/asn1peek.spec"

# Qt and Python extensions only require symbols available in Jammy's libstdc++.
# Leave the C++ runtime to the target OS so newer Mesa/LLVM drivers can use it.
rm -f "$APP/_internal/libstdc++.so.6"
[[ -x "$APP/asn1peek" ]] || { echo "[!] PyInstaller 未生成可执行文件" >&2; exit 1; }
printf '%s\n' "$INPUTS_HASH" > "$STAMP"
echo "[ok] bundle: $APP"
