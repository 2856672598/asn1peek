"""结构树视图：在 QTreeView 原生展开箭头下叠加经典树连接线。

Qt 6 内置样式（Fusion/Windows 等）只用缩进表达层级、不画分支连接线，
深树里「这一层属于谁」需要靠数缩进判断。这里在 ``drawBranches()`` 里补画：

- 竖线：祖先节点的「子树总线」，向下延伸到最后一个子节点所在行；
  路径上一层是父级最后一个子节点时该列不再延续（在父级的 └ 处收束）；
- 拐角横线：本行到父级列的 └/├ 折线，右端画到本行自身按钮格中心，
  有子节点时由随后绘制的展开箭头盖住线端，视觉上正好接在箭头上。

几何全部由 ``drawBranches()`` 传入的分支区矩形与层级推出（宽 = 层级数 ×
缩进），不依赖具体样式与字体，高 DPI 缩放、非默认缩进都自动跟随；线色取
前景色而非调色板 Mid（Yaru 等主题的 Mid 是白色，会与行背景同色不可见），
可用 ``set_connection_lines()`` 开关（「视图」菜单，默认开启）。
"""

from __future__ import annotations

from PySide6.QtCore import QModelIndex, QRect
from PySide6.QtGui import QColor, QPainter, QPalette, QPen
from PySide6.QtWidgets import QTreeView

# 连接线 = 前景色叠透明度：任何主题下都与行背景有对比度。
# 不能直接使用调色板 Mid：某些主题会将其设为接近白色，
# 与行背景对比不足时连接线会不可见。
_LINE_ALPHA = 90


def _contrast(a: QColor, b: QColor) -> int:
    """两色亮度差（0-255），用于挑选与背景对比更强的前景色。"""
    return abs(a.lightness() - b.lightness())


def line_color(palette: QPalette) -> QColor:
    """连接线颜色：取与行背景对比更强的前景色（Text/WindowText）+ 透明度。"""
    bg = palette.color(QPalette.ColorRole.Base)
    fg = palette.color(QPalette.ColorRole.Text)
    alt = palette.color(QPalette.ColorRole.WindowText)
    if _contrast(alt, bg) > _contrast(fg, bg):
        fg = alt
    color = QColor(fg)
    if color.alpha() == 0:  # 前景完全透明时退回不透明线，保证可见
        color = QColor(fg.rgb())
    color.setAlpha(_LINE_ALPHA)
    return color


def last_flags(index: QModelIndex) -> list[bool]:
    """路径上各层节点「是否为父级最后一个子节点」的标记。

    返回列表按层级索引：``flags[0]`` 恒为 False（根层无父级），
    ``flags[l]`` 对应层级 l（1 为顶层，len(flags)-1 即 index 自身层级）。
    """
    model = index.model()
    flags = [False]
    cur = index.siblingAtColumn(0) if index.column() != 0 else index
    while cur.parent().isValid():
        parent = cur.parent()
        flags.insert(1, cur.row() == model.rowCount(parent) - 1)
        cur = parent
    return flags


def connector_segments(
    rect: QRect, indent: int, is_last: list[bool]
) -> list[tuple[int, int, int, int]]:
    """一行的连接线段（x1, y1, x2, y2，视图坐标）。

    rect   : 分支区矩形（drawBranches 传入，宽 = 层级数 × indent）
    indent : 每级缩进像素
    is_last: ``last_flags()`` 的结果，len - 1 即本行层级
    """
    depth = len(is_last) - 1
    if depth <= 0 or indent <= 0:
        return []
    left = rect.left()
    top = rect.top()
    bottom = rect.bottom()
    mid_y = (top + bottom) // 2

    def cell_mid_x(level: int) -> int:
        """层级 level 节点按钮格的水平中心（level 0 为最左一格）。"""
        return left + level * indent + (indent - 1) // 2

    segments: list[tuple[int, int, int, int]] = []
    for level in range(1, depth + 1):
        x = cell_mid_x(level - 1)  # 该层节点挂在父级的按钮列上
        if not is_last[level]:
            segments.append((x, top, x, bottom))  # 总线穿过本行继续向下
        elif level == depth:
            segments.append((x, top, x, mid_y))  # 本例是最后子节点：└ 竖线
    segments.append(  # 拐角横线：父级列 → 本行按钮格中心
        (cell_mid_x(depth - 1), mid_y, cell_mid_x(depth), mid_y)
    )
    return segments


class Asn1TreeView(QTreeView):
    """带连接线的结构树视图（外观增强，模型/交互语义与 QTreeView 一致）。"""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._lines_enabled = True

    # ---- 连接线开关 ------------------------------------------------------

    def connection_lines(self) -> bool:
        return self._lines_enabled

    def set_connection_lines(self, enabled: bool) -> None:
        enabled = bool(enabled)
        if enabled == self._lines_enabled:
            return
        self._lines_enabled = enabled
        self.viewport().update()

    # ---- 绘制 ------------------------------------------------------------

    def drawBranches(
        self,
        painter: QPainter,
        rect: QRect,  # noqa: N802
        index: QModelIndex,
    ) -> None:
        if self._lines_enabled and index.column() == 0:
            self._draw_connectors(painter, rect, index)
        super().drawBranches(painter, rect, index)

    def _draw_connectors(self, painter: QPainter, rect: QRect, index: QModelIndex) -> None:
        if self.model() is None or rect.width() <= 0:
            return
        flags = last_flags(index)
        depth = len(flags) - 1
        if depth <= 0:
            return
        indent = max(1, rect.width() // (depth + 1))
        segments = connector_segments(rect, indent, flags)
        if not segments:
            return
        if self.isRightToLeft():  # 镜像到右侧（Qt 在 RTL 下从右往左排布）
            lx, rx = rect.left(), rect.right()
            segments = [(lx + rx - x1, y1, lx + rx - x2, y2) for x1, y1, x2, y2 in segments]
        color = line_color(self.palette())
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        painter.setPen(QPen(color, 1))
        for x1, y1, x2, y2 in segments:
            painter.drawLine(x1, y1, x2, y2)
        painter.restore()
