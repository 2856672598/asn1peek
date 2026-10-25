#!/usr/bin/env python3
"""SVG 图标 → PNG 栅格化（打包资产，offscreen 无头可用）。

用法：uv run python scripts/make_icon.py [svg 路径] [输出目录]
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QByteArray, QRect
from PySide6.QtGui import QGuiApplication, QImage, QPainter
from PySide6.QtSvg import QSvgRenderer

SIZES = (256, 128, 64)


def main() -> int:
    svg = Path(sys.argv[1] if len(sys.argv) > 1 else "assets/icon/asn1peek.svg")
    outdir = Path(sys.argv[2] if len(sys.argv) > 2 else svg.parent)
    QGuiApplication([])  # SVG 文本元素需要字体子系统
    renderer = QSvgRenderer(QByteArray(svg.read_bytes()))
    if not renderer.isValid():
        print(f"[!] 无效 SVG：{svg}")
        return 1
    for size in SIZES:
        image = QImage(size, size, QImage.Format.Format_ARGB32)
        image.fill(0)
        painter = QPainter(image)
        renderer.render(painter, QRect(0, 0, size, size))
        painter.end()
        out = outdir / f"{svg.stem}-{size}.png"
        if not image.save(str(out), "PNG"):
            print(f"[!] 保存失败：{out}")
            return 1
        print(f"[ok] {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
