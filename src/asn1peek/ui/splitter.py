"""分栏分隔条：相邻视图之间只画一条 1px 线。

Qt 默认每个子视图都带 1px ``StyledPanel`` 边框，QSplitter 手柄本身又有
4px 背景：相邻两栏之间会出现「两条线 + 灰色缝隙」。这里把边框交给
``LineSplitter`` 统一绘制：

- 手柄保留 5px 拖动热区（与原生 splitter 相近），但视觉上只在正中画
  一条 1px 线；
- 线色由调色板派生（Text 28% 混入 Base）：浅色主题下与原生的
  ``#B8B8B8`` 边框一致，深色主题自动适配；不使用 QPalette.Mid
  （Yaru 等主题下它可能是白色，会与背景同色不可见）；
- 悬停/拖动时线色改用 Highlight，弥补单线相对「凹槽 + 抓握点」损失的
  可拖拽提示。
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPainter, QPalette, QPen
from PySide6.QtWidgets import QSplitter, QSplitterHandle

_HANDLE_WIDTH = 5
_LINE_RATIO = 0.28  # 与原生 QFrame 边框在浅色主题下的观感一致


def divider_color(palette: QPalette) -> QColor:
    """分隔线颜色：前景色按比例混入底色，随浅/深主题自动适配。"""
    base = palette.color(QPalette.ColorRole.Base)
    text = palette.color(QPalette.ColorRole.Text)
    return QColor(
        round(text.red() * _LINE_RATIO + base.red() * (1 - _LINE_RATIO)),
        round(text.green() * _LINE_RATIO + base.green() * (1 - _LINE_RATIO)),
        round(text.blue() * _LINE_RATIO + base.blue() * (1 - _LINE_RATIO)),
    )


class _LineHandle(QSplitterHandle):
    """只画一条居中分隔线的手柄；保留原生拖动行为与调整光标。"""

    def __init__(self, orientation: Qt.Orientation, parent: QSplitter) -> None:
        super().__init__(orientation, parent)
        self._hover = False
        self._pressed = False

    # ---- 悬停/拖动反馈 ---------------------------------------------------

    def enterEvent(self, event) -> None:  # noqa: N802
        self._hover = True
        self.update()
        super().enterEvent(event)

    def leaveEvent(self, event) -> None:  # noqa: N802
        self._hover = False
        self.update()
        super().leaveEvent(event)

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton:
            self._pressed = True
            self.update()
        super().mousePressEvent(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802
        self._pressed = False
        self.update()
        super().mouseReleaseEvent(event)

    # ---- 绘制 ------------------------------------------------------------

    def paintEvent(self, event) -> None:  # noqa: N802
        palette = self.palette()
        rect = self.rect()
        painter = QPainter(self)
        painter.fillRect(rect, palette.color(QPalette.ColorRole.Base))

        active = self._hover or self._pressed
        color = palette.color(QPalette.ColorRole.Highlight) if active else divider_color(palette)
        painter.setPen(QPen(color, 1))
        if self.orientation() == Qt.Orientation.Horizontal:  # 左右分栏 → 竖线
            x = rect.center().x()
            painter.drawLine(x, rect.top(), x, rect.bottom())
        else:  # 上下分栏 → 横线
            y = rect.center().y()
            painter.drawLine(rect.left(), y, rect.right(), y)
        painter.end()


class LineSplitter(QSplitter):
    """相邻视图之间只显示一条 1px 分隔线的 QSplitter。"""

    def __init__(self, orientation: Qt.Orientation, parent=None) -> None:
        super().__init__(orientation, parent)
        self.setHandleWidth(_HANDLE_WIDTH)

    def createHandle(self) -> QSplitterHandle:  # noqa: N802
        return _LineHandle(self.orientation(), self)
