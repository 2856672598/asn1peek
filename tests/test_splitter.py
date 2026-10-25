"""分栏分隔条回归：相邻视图之间只保留一条 1px 线。

背景：QTreeView / QPlainTextEdit / QTextBrowser 默认各带 1px 边框，
QSplitter 手柄自身还有 4px 背景，界面上会出现「两条线 + 灰色缝隙」。
LineSplitter 把手柄背景与视图边框统一成一条居中细线，并保留拖动热区。
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import Qt
from PySide6.QtGui import QPalette
from PySide6.QtWidgets import QFrame, QLabel

from asn1peek.ui.splitter import LineSplitter, divider_color


def _split(qapp, orientation: Qt.Orientation) -> LineSplitter:
    split = LineSplitter(orientation)
    split.resize(300, 200)
    split.addWidget(QLabel("A"))
    split.addWidget(QLabel("B"))
    split.show()
    qapp.processEvents()
    return split


def test_handle_paints_single_centered_line(qapp):
    """横/纵分栏的手柄都只画一条居中细线，不再是双线或整条色带。"""
    for orientation, horizontal_split in (
        (Qt.Orientation.Horizontal, True),
        (Qt.Orientation.Vertical, False),
    ):
        split = _split(qapp, orientation)
        handle = split.handle(1)
        img = handle.grab().toImage()
        base = handle.palette().color(QPalette.ColorRole.Base)

        if horizontal_split:  # 左右分栏 → 竖向分隔线
            fixed = img.height() // 2
            positions = [x for x in range(img.width()) if img.pixelColor(x, fixed) != base]
            expected = (img.width() - 1) // 2
        else:  # 上下分栏 → 横向分隔线
            fixed = img.width() // 2
            positions = [y for y in range(img.height()) if img.pixelColor(fixed, y) != base]
            expected = (img.height() - 1) // 2

        assert positions == [expected], f"{orientation}: 应只有一条居中分隔线，实际 {positions}"
        assert img.pixelColor(
            positions[0] if horizontal_split else fixed,
            fixed if horizontal_split else positions[0],
        ) == divider_color(handle.palette())
        split.close()


def test_main_window_uses_single_line_layout(qapp):
    """主窗口接线：两处分栏都用 LineSplitter，三个视图不再自带边框。"""
    from asn1peek.ui.main_window import MainWindow

    win = MainWindow()
    win.show()
    qapp.processEvents()
    try:
        assert isinstance(win.centralWidget(), LineSplitter)
        right_split = win.hex_view.parentWidget()
        assert isinstance(right_split, LineSplitter)
        for view in (win.tree_view, win.hex_view, win.detail_panel.browser):
            assert view.frameShape() == QFrame.Shape.NoFrame
            assert view.frameWidth() == 0
    finally:
        win.close()
