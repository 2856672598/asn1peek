"""UI 主题色辅助（Hex 视图与详情面板共用）。"""

from __future__ import annotations

from PySide6.QtGui import QColor


def blend(fg: QColor, bg: QColor, ratio: float) -> QColor:
    """把前景色按 ratio 混入背景色（ratio=0 为纯背景，1 为纯前景）。"""
    return QColor(
        round(fg.red() * ratio + bg.red() * (1 - ratio)),
        round(fg.green() * ratio + bg.green() * (1 - ratio)),
        round(fg.blue() * ratio + bg.blue() * (1 - ratio)),
    )
